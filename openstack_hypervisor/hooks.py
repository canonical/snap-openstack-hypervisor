# Copyright 2022 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import binascii
import errno
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import stat
import string
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, Template
from netifaces import AF_INET, gateways, ifaddresses
from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError
from snaphelpers import Snap
from snaphelpers._conf import UnknownConfigKey

from openstack_hypervisor.log import setup_logging

UNSET = ""

# Any configuration read from snap will be a string and
# an empty string value for IPvAnyNetwork pydantic Field
# throws an error. So making 0.0.0.0/0 as kind of Empty
# or None for IPvAnyNetwork.
IPVANYNETWORK_UNSET = "0.0.0.0/0"

SECRETS = ["credentials.ovn-metadata-proxy-shared-secret"]

DEFAULT_SECRET_LENGTH = 32

# NOTE(dmitriis): there is currently no way to make sure this directory gets
# recreated on reboot which would normally be done via systemd-tmpfiles.
# mkdir -p /run/lock/snap.$SNAP_INSTANCE_NAME

# Copy TEMPLATE.qemu into the common directory. Libvirt generates additional
# policy dynamically which is why its apparmor directory is writeable under $SNAP_COMMON.
# Also copy other abstractions that are used by this template.
# rsync -rh $SNAP/etc/apparmor.d $SNAP_COMMON/etc

COMMON_DIRS = [
    # etc
    Path("etc/openvswitch"),
    Path("etc/ovn"),
    Path("etc/libvirt"),
    Path("etc/nova"),
    Path("etc/nova/nova.conf.d"),
    Path("etc/neutron"),
    Path("etc/neutron/neutron.conf.d"),
    Path("etc/ssl/certs"),
    Path("etc/ssl/private"),
    Path("etc/ceilometer"),
    # log
    Path("log/libvirt/qemu"),
    Path("log/ovn"),
    Path("log/openvswitch"),
    Path("log/nova"),
    Path("log/neutron"),
    # run
    Path("run/ovn"),
    Path("run/openvswitch"),
    # lock
    Path("lock"),
    # Instances
    Path("lib/nova/instances"),
]

DATA_DIRS = [
    Path("lib/libvirt/images"),
    Path("lib/ovn"),
    Path("lib/neutron"),
    Path("run/hypervisor-config"),
]
SECRET_XML = string.Template(
    """
<secret ephemeral='no' private='no'>
   <uuid>$uuid</uuid>
   <usage type='ceph'>
     <name>client.cinder-ceph secret</name>
   </usage>
</secret>
"""
)

# As defined in the snap/snapcraft.yaml
MONITORING_SERVICES = [
    "libvirt-exporter",
    "ovs-exporter",
]


def _generate_secret(length: int = DEFAULT_SECRET_LENGTH) -> str:
    """Generate a secure secret.

    :param length: length of generated secret
    :type length: int
    :return: string containing the generated secret
    """
    return "".join(secrets.choice(string.ascii_letters + string.digits) for i in range(length))


def _mkdirs(snap: Snap) -> None:
    """Ensure directories requires for operator of snap exist.

    :param snap: the snap instance
    :type snap: Snap
    :return: None
    """
    for dir in COMMON_DIRS:
        os.makedirs(snap.paths.common / dir, exist_ok=True)
    for dir in DATA_DIRS:
        os.makedirs(snap.paths.data / dir, exist_ok=True)


def _setup_secrets(snap: Snap) -> None:
    """Setup any secrets needed for snap operation.

    :param snap: the snap instance
    :type snap: Snap
    :return: None
    """
    credentials = snap.config.get_options("credentials")

    for secret in SECRETS:
        if not credentials.get(secret):
            snap.config.set({secret: _generate_secret()})


def _get_default_gw_iface_fallback() -> Optional[str]:
    """Returns the default gateway interface.

    Parses the /proc/net/route table to determine the interface with a default
    route. The interface with the default route will have a destination of 0x000000,
    a mask of 0x000000 and will have flags indicating RTF_GATEWAY and RTF_UP.

    :return Optional[str, None]: the name of the interface the default gateway or
            None if one cannot be found.
    """
    # see include/uapi/linux/route.h in kernel source for more explanation
    RTF_UP = 0x1  # noqa - route is usable
    RTF_GATEWAY = 0x2  # noqa - destination is a gateway

    iface = None
    with open("/proc/net/route", "r") as f:
        contents = [line.strip() for line in f.readlines() if line.strip()]

        entries = []
        # First line is a header line of the table contents. Note, we skip blank entries
        # by default there's an extra column due to an extra \t character for the table
        # contents to line up. This is parsing the /proc/net/route and creating a set of
        # entries. Each entry is a dict where the keys are table header and the values
        # are the values in the table rows.
        header = [col.strip().lower() for col in contents[0].split("\t") if col]
        for row in contents[1:]:
            cells = [col.strip() for col in row.split("\t") if col]
            entries.append(dict(zip(header, cells)))

        def is_up(flags: str) -> bool:
            return int(flags, 16) & RTF_UP == RTF_UP

        def is_gateway(flags: str) -> bool:
            return int(flags, 16) & RTF_GATEWAY == RTF_GATEWAY

        # Check each entry to see if it has the default gateway. The default gateway
        # will have destination and mask set to 0x00, will be up and is noted as a
        # gateway.
        for entry in entries:
            if int(entry.get("destination", 0xFF), 16) != 0:
                continue
            if int(entry.get("mask", 0xFF), 16) != 0:
                continue
            flags = entry.get("flags", 0x00)
            if is_up(flags) and is_gateway(flags):
                iface = entry.get("iface", None)
                break

    return iface


def _get_local_ip_by_default_route() -> str:
    """Get IP address of host associated with default gateway."""
    interface = "lo"
    ip = "127.0.0.1"

    # TOCHK: Gathering only IPv4
    default_gateways = gateways().get("default", {})
    if default_gateways and AF_INET in default_gateways:
        interface = gateways()["default"][AF_INET][1]
    else:
        # There are some cases where netifaces doesn't return the machine's
        # default gateway, but it does exist. Let's check the /proc/net/route
        # table to see if we can find the proper gateway.
        interface = _get_default_gw_iface_fallback() or "lo"

    ip_list = ifaddresses(interface)[AF_INET]
    if len(ip_list) > 0 and "addr" in ip_list[0]:
        ip = ip_list[0]["addr"]

    return ip


DEFAULT_CONFIG = {
    # Keystone
    "identity.admin-role": "Admin",
    "identity.auth-url": "http://localhost:5000/v3",
    "identity.username": UNSET,
    "identity.password": UNSET,
    # keystone-k8s defaults
    "identity.user-domain-id": UNSET,
    "identity.user-domain-name": "service_domain",
    "identity.project-name": "services",
    "identity.project-domain-id": UNSET,
    "identity.project-domain-name": "service_domain",
    "identity.region-name": "RegionOne",
    # Messaging
    "rabbitmq.url": "rabbit://localhost:5672",
    # Nova
    "compute.cpu-mode": "host-model",
    "compute.virt-type": "auto",
    "compute.cpu-models": UNSET,
    "compute.spice-proxy-address": _get_local_ip_by_default_route,  # noqa: F821
    "compute.rbd_user": "nova",
    "compute.rbd_secret_uuid": UNSET,
    "compute.rbd_key": UNSET,
    # Neutron
    "network.physnet-name": "physnet1",
    "network.external-bridge": "br-ex",
    "network.external-bridge-address": IPVANYNETWORK_UNSET,
    "network.dns-domain": "openstack.local",
    "network.dns-servers": "8.8.8.8",
    "network.ovn-sb-connection": "tcp:127.0.0.1:6642",
    "network.ovn-cert": UNSET,
    "network.ovn-key": UNSET,
    "network.ovn-cacert": UNSET,
    "network.enable-gateway": False,
    "network.ip-address": _get_local_ip_by_default_route,  # noqa: F821
    "network.external-nic": UNSET,
    # Monitoring
    "monitoring.enable": False,
    # General
    "logging.debug": False,
    "node.fqdn": socket.getfqdn,
    "node.ip-address": _get_local_ip_by_default_route,  # noqa: F821
    # TLS
    # Telemetry
    "telemetry.enable": False,
    "telemetry.publisher-secret": UNSET,
}


# Required config can be a section like "identity" in which case all keys must
# be set or a single key like "identity.password".
REQUIRED_CONFIG = {
    "nova-compute": ["identity.password", "identity.username", "identity", "rabbitmq.url"],
    "nova-api-metadata": [
        "identity.password",
        "identity.username",
        "identity",
        "rabbitmq.url",
        "network",
    ],
    "neutron-ovn-metadata-agent": ["credentials", "network", "node", "network.ovn_key"],
    "ceilometer-compute-agent": [
        "identity.password",
        "identity.username",
        "identity",
        "rabbitmq.url",
    ],
}


def install(snap: Snap) -> None:
    """Runs the 'install' hook for the snap.

    The 'install' hook will create the configuration directory, located
    at $SNAP_COMMON/etc and set the default configuration options.

    :param snap: the snap instance
    :type snap: Snap
    :return: None
    """
    setup_logging(snap.paths.common / "hooks.log")
    logging.info("Running install hook")
    _mkdirs(snap)
    _update_default_config(snap)


def _get_template(snap: Snap, template: str) -> Template:
    """Returns the Jinja2 template to render.

    Locates the jinja template within the snap to load and returns
    the Template to the caller. This will look for the template in
    the 'templates' directory of the snap.

    :param snap: the snap to provide context
    :type snap: Snap
    :param template: the name of the template to locate
    :type template: str
    :return: the Template to use to render.
    :rtype: Template
    """
    template_dir = snap.paths.snap / "templates"
    env = Environment(loader=FileSystemLoader(searchpath=str(template_dir)))
    return env.get_template(template)


def _context_compat(context: Dict[str, Any]) -> Dict[str, Any]:
    """Manipulate keys in context to be Jinja2 template compatible.

    Jinja2 templates using dot notation need to have Python compatible
    keys; '_' is not accepted in a key name for snapctl so we have to use
    '-' instead.  Remap these back to '_' for template usage.

    :return: dictionary in Jinja2 compatible format
    :rtype: Dict
    """
    clean_context = {}
    for key, value in context.items():
        key = key.replace("-", "_")
        if not isinstance(value, Dict):
            clean_context[key] = value
        else:
            clean_context[key] = _context_compat(value)
    return clean_context


TEMPLATES = {
    Path("etc/nova/nova.conf"): {
        "template": "nova.conf.j2",
        "services": ["nova-compute", "nova-api-metadata"],
    },
    Path("etc/neutron/neutron.conf"): {
        "template": "neutron.conf.j2",
        "services": ["neutron-ovn-metadata-agent"],
    },
    Path("etc/neutron/neutron_ovn_metadata_agent.ini"): {
        "template": "neutron_ovn_metadata_agent.ini.j2",
        "services": ["neutron-ovn-metadata-agent"],
    },
    Path("etc/libvirt/libvirtd.conf"): {"template": "libvirtd.conf.j2", "services": ["libvirtd"]},
    Path("etc/libvirt/qemu.conf"): {
        "template": "qemu.conf.j2",
    },
    Path("etc/libvirt/virtlogd.conf"): {"template": "virtlogd.conf.j2", "services": ["virtlogd"]},
    Path("etc/openvswitch/system-id.conf"): {
        "template": "system-id.conf.j2",
    },
    Path("etc/ceilometer/ceilometer.conf"): {
        "template": "ceilometer.conf.j2",
        "services": ["ceilometer-compute-agent"],
    },
    Path("etc/ceilometer/polling.yaml"): {
        "template": "polling.yaml.j2",
        "services": ["ceilometer-compute-agent"],
    },
}


class RestartOnChange(object):
    """Restart services based on file context changes."""

    def __init__(self, snap: Snap, files: dict, exclude_services: list = None):
        self.snap = snap
        self.files = files
        self.file_hash = {}
        self.exclude_services = exclude_services or []

    def __enter__(self):
        """Record all file hashes on entry."""
        for file in self.files:
            full_path = self.snap.paths.common / file
            if full_path.exists():
                with open(full_path, "rb") as f:
                    self.file_hash[file] = hashlib.sha256(f.read()).hexdigest()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """Restart any services where hashes have changed."""
        restart_services = []
        for file in self.files:
            full_path = self.snap.paths.common / file
            if full_path.exists():
                if file not in self.file_hash:
                    restart_services.extend(self.files[file].get("services", []))
                    continue
                with open(full_path, "rb") as f:
                    new_hash = hashlib.sha256(f.read()).hexdigest()
                    if new_hash != self.file_hash[file]:
                        restart_services.extend(self.files[file].get("services", []))

        restart_services = set([s for s in restart_services if s not in self.exclude_services])
        services = self.snap.services.list()
        for service in restart_services:
            logging.info(f"Restarting {service}")
            services[service].stop()
            services[service].start(enable=True)


def _update_default_config(snap: Snap) -> None:
    """Add any missing default configuration keys.

    :param snap: the snap reference
    :type snap: Snap
    :return: None
    """
    option_keys = set([k.split(".")[0] for k in DEFAULT_CONFIG.keys()])
    current_options = snap.config.get_options(*option_keys)
    missing_options = {}
    for option, default in DEFAULT_CONFIG.items():
        if option not in current_options:
            if callable(default):
                default = default()
            if default != UNSET:
                missing_options.update({option: default})

    if missing_options:
        logging.info(f"Setting config: {missing_options}")
        snap.config.set(missing_options)


def _add_ip_to_interface(interface: str, cidr: str) -> None:
    """Add IP to interface and set link to up.

    Deletes any existing IPs on the interface and set IP
    of the interface to cidr.

    :param interface: interface name
    :type interface: str
    :param cidr: network address
    :type cidr: str
    :return: None
    """
    logging.debug(f"Adding  ip {cidr} to {interface}")
    ipr = IPRoute()
    dev = ipr.link_lookup(ifname=interface)[0]
    ip_mask = cidr.split("/")
    try:
        ipr.addr("add", index=dev, address=ip_mask[0], mask=int(ip_mask[1]))
    except NetlinkError as e:
        if e.code != errno.EEXIST:
            raise e

    ipr.link("set", index=dev, state="up")


def _delete_ips_from_interface(interface: str) -> None:
    """Remove all IPs from interface."""
    logging.debug(f"Resetting interface {interface}")
    ipr = IPRoute()
    dev = ipr.link_lookup(ifname=interface)[0]
    ipr.flush_addr(index=dev)


def _add_iptable_postrouting_rule(cidr: str, comment: str) -> None:
    """Add postrouting iptable rule.

    Add new postiprouting iptable rule, if it does not exist, to allow traffic
    for cidr network.
    """
    executable = "iptables-legacy"
    rule_def = [
        "POSTROUTING",
        "-w",
        "-t",
        "nat",
        "-s",
        cidr,
        "-j",
        "MASQUERADE",
        "-m",
        "comment",
        "--comment",
        comment,
    ]
    found = False
    try:
        cmd = [executable, "--check"]
        cmd.extend(rule_def)
        logging.debug(cmd)
        subprocess.run(cmd, capture_output=True, check=True)
    except subprocess.CalledProcessError as e:
        # --check has an RC of 1 if the rule does not exist
        if e.returncode == 1 and re.search(r"No.*match by that name", e.stderr.decode()):
            logging.debug(f"Postrouting iptable rule for {cidr} missing")
            found = False
        else:
            logging.warning(f"Failed to lookup postrouting iptable rule for {cidr}")
    else:
        # If not exception was raised then the rule exists.
        logging.debug(f"Found existing postrouting rule for {cidr}")
        found = True
    if not found:
        logging.debug(f"Adding postrouting iptable rule for {cidr}")
        cmd = [executable, "--append"]
        cmd.extend(rule_def)
        logging.debug(cmd)
        subprocess.check_call(cmd)


def _delete_iptable_postrouting_rule(comment: str) -> None:
    """Delete postrouting iptable rules based on comment."""
    logging.debug("Resetting iptable rules added by openstack-hypervisor")
    if not comment:
        return

    try:
        cmd = [
            "iptables-legacy",
            "-t",
            "nat",
            "-n",
            "-v",
            "-L",
            "POSTROUTING",
            "--line-numbers",
        ]
        process = subprocess.run(cmd, capture_output=True, text=True, check=True)
        iptable_rules = process.stdout.strip()

        line_numbers = [
            line.split(" ")[0] for line in iptable_rules.split("\n") if comment in line
        ]

        # Delete line numbers in descending order
        # If a lower numbered line number is deleted, iptables
        # changes lines numbers of high numbered rules.
        line_numbers.sort(reverse=True)
        for number in line_numbers:
            delete_rule_cmd = [
                "iptables-legacy",
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                number,
            ]
            logging.debug(f"Deleting iptable rule: {delete_rule_cmd}")
            subprocess.check_call(delete_rule_cmd)
    except subprocess.CalledProcessError as e:
        logging.info(f"Error in deletion of IPtable rule: {e.stderr}")


def _configure_ovn_base(snap: Snap) -> None:
    """Configure OVS/OVN.

    :param snap: the snap reference
    :type snap: Snap
    :return: None
    """
    # Check for network specific IP address
    ovn_encap_ip = snap.config.get("network.ip-address")
    if not ovn_encap_ip:
        # Fallback to general node IP
        ovn_encap_ip = snap.config.get("node.ip-address")
    system_id = snap.config.get("node.fqdn")
    if not ovn_encap_ip and system_id:
        logging.info("OVN IP and System ID not configured, skipping.")
        return
    logging.info(
        "Configuring Open vSwitch geneve tunnels and system id. "
        f"ovn-encap-ip = {ovn_encap_ip}, system-id = {system_id}"
    )
    subprocess.check_call(
        [
            "ovs-vsctl",
            "--retry",
            "set",
            "open",
            ".",
            "external_ids:ovn-encap-type=geneve",
            "--",
            "set",
            "open",
            ".",
            f"external_ids:ovn-encap-ip={ovn_encap_ip}",
            "--",
            "set",
            "open",
            ".",
            f"external_ids:system-id={system_id}",
            "--",
            "set",
            "open",
            ".",
            "external_ids:ovn-match-northd-version=true",
        ]
    )
    sb_conn = snap.config.get("network.ovn-sb-connection")
    if not sb_conn:
        logging.info("OVN SB connection URL not configured, skipping.")
        return
    subprocess.check_call(
        ["ovs-vsctl", "--retry", "set", "open", ".", f"external_ids:ovn-remote={sb_conn}"]
    )


def _list_bridge_ifaces(bridge_name: str) -> list:
    """Return a list of interfaces attached to given bridge.

    :param bridge_name: Name of bridge.
    """
    ifaces = (
        subprocess.check_output(["ovs-vsctl", "--retry", "list-ifaces", bridge_name])
        .decode()
        .split()
    )
    return sorted(ifaces)


def _add_interface_to_bridge(external_bridge: str, external_nic: str) -> None:
    """Add an interface to a given bridge.

    :param bridge_name: Name of bridge.
    :param external_nic: Name of nic.
    """
    if external_nic in _list_bridge_ifaces(external_bridge):
        logging.warning(f"Interface {external_nic} already connected to {external_bridge}")
    else:
        logging.warning(f"Adding interface {external_nic} to {external_bridge}")
        cmd = [
            "ovs-vsctl",
            "--retry",
            "add-port",
            external_bridge,
            external_nic,
            "--",
            "set",
            "Port",
            external_nic,
            "external-ids:microstack-function=ext-port",
        ]
        subprocess.check_call(cmd)


def _del_interface_from_bridge(external_bridge: str, external_nic: str) -> None:
    """Remove an interface from  a given bridge.

    :param bridge_name: Name of bridge.
    :param external_nic: Name of nic.
    """
    if external_nic in _list_bridge_ifaces(external_bridge):
        logging.warning(f"Removing interface {external_nic} from {external_bridge}")
        subprocess.check_call(["ovs-vsctl", "--retry", "del-port", external_bridge, external_nic])
    else:
        logging.warning(f"Interface {external_nic} not connected to {external_bridge}")


def _get_external_ports_on_bridge(bridge: str) -> list:
    """Get microstack managed external port on bridge.

    :param bridge_name: Name of bridge.
    """
    cmd = [
        "ovs-vsctl",
        "-f",
        "json",
        "find",
        "Port",
        "external-ids:microstack-function=ext-port",
    ]
    output = json.loads(subprocess.check_output(cmd))
    name_idx = output["headings"].index("name")
    external_nics = [r[name_idx] for r in output["data"]]
    bridge_ifaces = _list_bridge_ifaces(bridge)
    return [i for i in bridge_ifaces if i in external_nics]


def _ensure_single_nic_on_bridge(external_bridge: str, external_nic: str) -> None:
    """Ensure nic is attached to bridge and no other microk8s managed nics.

    :param bridge_name: Name of bridge.
    :param external_nic: Name of nic.
    """
    external_ports = _get_external_ports_on_bridge(external_bridge)
    if external_nic in external_ports:
        logging.debug(f"{external_nic} already attached to {external_bridge}")
    else:
        _add_interface_to_bridge(external_bridge, external_nic)
    for p in external_ports:
        if p != external_nic:
            logging.debug(f"Removing additional external port {p} from {external_bridge}")
            _del_interface_from_bridge(external_bridge, p)


def _del_external_nics_from_bridge(external_bridge: str) -> None:
    """Delete all microk8s managed external nics from bridge.

    :param bridge_name: Name of bridge.
    """
    for p in _get_external_ports_on_bridge(external_bridge):
        _del_interface_from_bridge(external_bridge, p)


def _configure_ovn_external_networking(snap: Snap) -> None:
    """Configure OVS/OVN external networking.

    :param snap: the snap reference
    :type snap: Snap
    :return: None
    """
    # TODO:
    # Deal with multiple external networks.
    # Deal with wiring of hardware port to each bridge.
    external_bridge = snap.config.get("network.external-bridge")
    physnet_name = snap.config.get("network.physnet-name")
    try:
        external_nic = snap.config.get("network.external-nic")
    except UnknownConfigKey:
        external_nic = None
    if not external_bridge and physnet_name:
        logging.info("OVN external networking not configured, skipping.")
        return
    subprocess.check_call(
        [
            "ovs-vsctl",
            "--retry",
            "--may-exist",
            "add-br",
            external_bridge,
            "--",
            "set",
            "bridge",
            external_bridge,
            "datapath_type=system",
            "protocols=OpenFlow13,OpenFlow15",
        ]
    )
    subprocess.check_call(
        [
            "ovs-vsctl",
            "--retry",
            "set",
            "open",
            ".",
            f"external_ids:ovn-bridge-mappings={physnet_name}:{external_bridge}",
        ]
    )

    external_bridge_address = snap.config.get("network.external-bridge-address")
    comment = "openstack-hypervisor external network rule"
    # Consider 0.0.0.0/0 as IPvAnyNetwork None
    if external_bridge_address == IPVANYNETWORK_UNSET:
        logging.info(f"Resetting external bridge {external_bridge} configuration")
        _delete_ips_from_interface(external_bridge)
        _delete_iptable_postrouting_rule(comment)
        if external_nic:
            logging.info(f"Adding {external_nic} to {external_bridge}")
            _ensure_single_nic_on_bridge(external_bridge, external_nic)
        else:
            logging.info(f"Removing nics from {external_bridge}")
            _del_external_nics_from_bridge(external_bridge)
    else:
        logging.info(f"configuring external bridge {external_bridge}")
        _add_ip_to_interface(external_bridge, external_bridge_address)
        external_network = ipaddress.ip_interface(external_bridge_address).network
        _add_iptable_postrouting_rule(str(external_network), comment)

    if snap.config.get("network.enable-gateway"):
        logging.info("Enabling OVS as external gateway")
        subprocess.check_call(
            [
                "ovs-vsctl",
                "--retry",
                "set",
                "open",
                ".",
                "external_ids:ovn-cms-options=enable-chassis-as-gw",
            ]
        )
    else:
        logging.info("Disabling OVS as external gateway")
        subprocess.check_call(
            [
                "ovs-vsctl",
                "--retry",
                "remove",
                "open",
                ".",
                "external_ids",
                "ovn-cms-options",
                "enable-chassis-as-gw",
            ]
        )


def _configure_ovn_tls(snap: Snap) -> None:
    """Configure OVS/OVN TLS.

    :param snap: the snap reference
    :type snap: Snap
    :return: None
    """

    def _parse_tls(config_key: str) -> str:
        """Parse Base64 encoded key or cert.

        :param config_key: base64 encoded data (or UNSET)
        :type config_key: str
        :return: decoded data or None
        :rtype: str
        """
        try:
            return base64.b64decode(snap.config.get(config_key))
        except (binascii.Error, TypeError):
            pass

    try:
        ovn_cert = _parse_tls("network.ovn-cert")
        ovn_cacert = _parse_tls("network.ovn-cacert")
        ovn_key = _parse_tls("network.ovn-key")
    except UnknownConfigKey:
        logging.info("OVN TLS configuration incomplete, skipping.")
        return
    if not all(
        (
            ovn_cert,
            ovn_cacert,
            ovn_key,
        )
    ):
        logging.info("OVN TLS configuration incomplete, skipping.")
        return

    ssl_key = snap.paths.common / Path("etc/ssl/private/ovn-key.pem")
    ssl_cert = snap.paths.common / Path("etc/ssl/certs/ovn-cert.pem")
    ssl_cacert = snap.paths.common / Path("etc/ssl/certs/ovn-cacert.pem")

    with open(ssl_key, "wb") as f:
        f.write(ovn_key)
    with open(ssl_cert, "wb") as f:
        f.write(ovn_cert)
    with open(ssl_cacert, "wb") as f:
        f.write(ovn_cacert)

    subprocess.check_call(
        [
            "ovs-vsctl",
            "--retry",
            "set-ssl",
            str(ssl_key),
            str(ssl_cert),
            str(ssl_cacert),
        ]
    )


def _is_kvm_api_available() -> bool:
    """Determine whether KVM is supportable."""
    kvm_devpath = "/dev/kvm"
    if not os.path.exists(kvm_devpath):
        logging.warning(f"{kvm_devpath} does not exist")
        return False
    elif not os.access(kvm_devpath, os.R_OK | os.W_OK):
        logging.warning(f"{kvm_devpath} is not RW-accessible")
        return False
    kvm_dev = os.stat(kvm_devpath)
    if not stat.S_ISCHR(kvm_dev.st_mode):
        logging.warning(f"{kvm_devpath} is not a character device")
        return False
    major = os.major(kvm_dev.st_rdev)
    minor = os.minor(kvm_dev.st_rdev)
    if major != 10:
        logging.warning(f"{kvm_devpath} has an unexpected major number: {major}")
        return False
    elif minor != 232:
        logging.warning(f"{kvm_devpath} has an unexpected minor number: {minor}")
        return False
    return True


def _is_hw_virt_supported() -> bool:
    """Determine whether hardware virt is supported."""
    cpu_info = json.loads(subprocess.check_output(["lscpu", "-J"]))["lscpu"]
    architecture = next(filter(lambda x: x["field"] == "Architecture:", cpu_info), None)[
        "data"
    ].split()
    flags = next(filter(lambda x: x["field"] == "Flags:", cpu_info), None)
    if flags is not None:
        flags = flags["data"].split()

    vendor_id = next(filter(lambda x: x["field"] == "Vendor ID:", cpu_info), None)
    if vendor_id is not None:
        vendor_id = vendor_id["data"]

    # Mimic virt-host-validate code (from libvirt) and assume nested
    # support on ppc64 LE or BE.
    if architecture in ["ppc64", "ppc64le"]:
        return True
    elif vendor_id is not None and flags is not None:
        if vendor_id == "AuthenticAMD" and "svm" in flags:
            return True
        elif vendor_id == "GenuineIntel" and "vmx" in flags:
            return True
        elif vendor_id == "IBM/S390" and "sie" in flags:
            return True
        elif vendor_id == "ARM":
            # ARM 8.3-A added nested virtualization support but it is yet
            # to land upstream https://lwn.net/Articles/812280/ at the time
            # of writing (Nov 2020).
            logging.warning(
                "Nested virtualization is not supported on ARM" " - will use emulation"
            )
            return False
        else:
            logging.warning(
                "Unable to determine hardware virtualization"
                f' support by CPU vendor id "{vendor_id}":'
                " assuming it is not supported."
            )
            return False
    else:
        logging.warning(
            "Unable to determine hardware virtualization support"
            " by the output of lscpu: assuming it is not"
            " supported"
        )
        return False


def _set_secret(conn, secret_uuid: str, secret_value: str) -> None:
    """Set the ceph access secret in libvirt."""
    logging.info(f"Setting secret {secret_uuid}")
    new_secret = conn.secretDefineXML(SECRET_XML.substitute(uuid=secret_uuid))
    # nova assumes the secret is raw and always encodes it *1, so decode it
    # before storing it.
    # *1 https://opendev.org/openstack/nova/src/branch/stable/2023.1/nova/
    #           virt/libvirt/imagebackend.py#L1110
    new_secret.setValue(base64.b64decode(secret_value))


def _get_libvirt():
    # Lazy import libvirt otherwise snap will not build
    import libvirt

    return libvirt


def _ensure_secret(secret_uuid: str, secret_value: str) -> None:
    """Ensure libvirt has the ceph access secret with the correct value."""
    libvirt = _get_libvirt()
    conn = libvirt.open("qemu:///system")
    # Check if secret exists
    if secret_uuid in conn.listSecrets():
        logging.info(f"Found secret {secret_uuid}")
        # check secret matches
        secretobj = conn.secretLookupByUUIDString(secret_uuid)
        try:
            secret = secretobj.value()
        except libvirt.libvirtError as e:
            if e.get_error_code() == libvirt.VIR_ERR_NO_SECRET:
                logging.info(f"Secret {secret_uuid} has no value.")
                secret = None
            else:
                raise
        # Secret is stored raw so encode it before comparison.
        if secret == base64.b64encode(secret_value.encode()):
            logging.info(f"Secret {secret_uuid} has desired value.")
        else:
            logging.info(f"Secret {secret_uuid} has wrong value, replacing.")
            secretobj.undefine()
            _set_secret(conn, secret_uuid, secret_value)
    else:
        logging.info(f"Secret {secret_uuid} not found, creating.")
        _set_secret(conn, secret_uuid, secret_value)


def _configure_ceph(snap) -> None:
    """Configure ceph client.

    :param snap: the snap reference
    :type snap: Snap
    :return: None
    """
    logging.info("Configuring ceph access")
    context = (
        snap.config.get_options(
            "compute",
        )
        .as_dict()
        .get("compute")
    )
    if all(k in context for k in ("rbd-key", "rbd-secret-uuid")):
        _ensure_secret(context["rbd-secret-uuid"], context["rbd-key"])


def _configure_kvm(snap: Snap) -> None:
    """Configure KVM hardware virtualization.

    :param snap: the snap reference
    :type snap: Snap
    :return: None
    """
    logging.info("Checking virtualization extensions presence on the host")
    # Use KVM if it is supported, alternatively fall back to software
    # emulation.
    if _is_hw_virt_supported() and _is_kvm_api_available():
        logging.info("Hardware virtualization is supported - KVM will be used.")
        snap.config.set({"compute.virt-type": "kvm"})
    else:
        logging.warning(
            "Hardware virtualization is not supported - software" " emulation will be used."
        )
        snap.config.set({"compute.virt-type": "qemu"})


def _configure_monitoring_services(snap: Snap) -> None:
    """Configure all the monitoring services.

    :param snap: the snap reference
    :type snap: Snap
    :return: None
    """
    services = snap.services.list()
    enable_monitoring = snap.config.get("monitoring.enable")
    if enable_monitoring:
        logging.info("Enabling all exporter services.")
        for service in MONITORING_SERVICES:
            services[service].start(enable=True)
    else:
        logging.info("Disabling all exporter services.")
        for service in MONITORING_SERVICES:
            services[service].stop(disable=True)


def services() -> List[str]:
    """List of services managed by hooks."""
    return sorted(list(set([w for v in TEMPLATES.values() for w in v.get("services", [])])))


def _section_complete(section: str, context: dict) -> bool:
    """Check section is present in context and has no unset keys."""
    if not context.get(section):
        return False
    return len([v for v in context[section].values() if v == UNSET]) == 0


def _check_config_present(key: str, context: dict) -> bool:
    """Check key or section is in context and set."""
    present = False
    try:
        if len(key.split(".")) == 1:
            if _section_complete(key, context):
                present = True
        else:
            section, skey = key.split(".")
            if context[section][skey] != UNSET:
                present = True
    except KeyError:
        present = False
    return present


def _services_not_ready(context: dict) -> List[str]:
    """Check if any services are missing keys they need to function."""
    logging.warning(f"Context {context}")
    not_ready = []
    for svc in services():
        for required in REQUIRED_CONFIG.get(svc, []):
            if not _check_config_present(required, context):
                not_ready.append(svc)
    return sorted(list(set(not_ready)))


def _services_not_enabled_by_config(context: dict) -> List[str]:
    """Check if services are enabled by configuration."""
    not_enabled = []
    if not context.get("telemetry", {}).get("enable"):
        not_enabled.append("ceilometer-compute-agent")

    return not_enabled


def configure(snap: Snap) -> None:
    """Runs the `configure` hook for the snap.

    This method is invoked when the configure hook is executed by the snapd
    daemon. The `configure` hook is invoked when the user runs a sudo snap
    set openstack-hypervisor.<foo> setting.

    :param snap: the snap reference
    :type snap: Snap
    :return: None
    """
    setup_logging(snap.paths.common / "hooks.log")
    logging.info("Running configure hook")

    _mkdirs(snap)
    _update_default_config(snap)
    _setup_secrets(snap)

    context = snap.config.get_options(
        "compute",
        "network",
        "identity",
        "logging",
        "node",
        "rabbitmq",
        "credentials",
        "telemetry",
        "monitoring",
    ).as_dict()

    # Add some general snap path information
    context.update(
        {
            "snap_common": str(snap.paths.common),
            "snap_data": str(snap.paths.data),
            "snap": str(snap.paths.snap),
        }
    )
    context = _context_compat(context)
    logging.info(context)
    exclude_services = _services_not_ready(context)
    exclude_services.extend(_services_not_enabled_by_config(context))
    logging.warning(f"{exclude_services} are missing required config, stopping")
    services = snap.services.list()
    for service in exclude_services:
        services[service].stop()

    with RestartOnChange(snap, TEMPLATES, exclude_services):
        for config_file, template in TEMPLATES.items():
            template = _get_template(snap, template.get("template"))
            config_file = snap.paths.common / config_file
            logging.info(f"Rendering {config_file}")
            try:
                output = template.render(context)
                with open(config_file, "w+") as f:
                    f.write(output)
            except:  # noqa
                logging.exception(
                    "An error occurred when attempting to render the mysql configuration file."
                )
                raise

    _configure_ovn_base(snap)
    _configure_ovn_external_networking(snap)
    _configure_ovn_tls(snap)
    _configure_kvm(snap)
    _configure_monitoring_services(snap)
    _configure_ceph(snap)
