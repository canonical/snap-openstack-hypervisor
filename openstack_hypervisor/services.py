# SPDX-FileCopyrightText: 2022 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import base64
import binascii
import configparser
import logging
import os
import subprocess
import sys
import time
from functools import partial
from pathlib import Path

from snaphelpers import Snap, UnknownConfigKey

from openstack_hypervisor.log import setup_logging
from openstack_hypervisor.mount_validation import validate_instances_mount

OVSDB_SCHEMA_TIMEOUT = 60
OVSDB_SCHEMA_CHECK_INTERVAL = 2


def entry_point(service_class):
    """Entry point wrapper for services."""
    service = service_class()
    exit_code = service.run(Snap())
    sys.exit(exit_code)


class OpenStackService:
    """Base service object for OpenStack daemons."""

    conf_files = []
    conf_dirs = []
    extra_args = []

    executable = None

    def run(self, snap: Snap) -> int:
        """Runs the OpenStack service.

        Invoked when this service is started.

        :param snap: the snap context
        :type snap: Snap
        :return: exit code of the process
        :rtype: int
        """
        setup_logging(snap.paths.common / f"{self.executable.name}-{snap.name}.log")

        if not self.preflight(snap):
            return 1

        args = []
        for conf_file in self.conf_files:
            args.extend(
                [
                    "--config-file",
                    str(snap.paths.common / conf_file),
                ]
            )
        for conf_dir in self.conf_dirs:
            args.extend(
                [
                    "--config-dir",
                    str(snap.paths.common / conf_dir),
                ]
            )

        executable = snap.paths.snap / self.executable

        cmd = [str(executable)]
        cmd.extend(args)
        cmd.extend(self.extra_args)
        completed_process = subprocess.run(cmd)

        logging.info(f"Exiting with code {completed_process.returncode}")
        return completed_process.returncode

    def preflight(self, snap: Snap) -> bool:
        """Preflight checks before starting the service.

        Return True to proceed with startup. Return False to abort.
        """
        return True


class NovaComputeService(OpenStackService):
    """A python service object used to run the nova-compute daemon."""

    conf_files = [
        Path("etc/nova/nova.conf"),
    ]
    conf_dirs = [
        Path("etc/nova/nova.conf.d"),
    ]

    executable = Path("usr/bin/nova-compute")

    def preflight(self, snap: Snap) -> bool:
        """Validate any configured mount for the Nova instances path."""
        instances_path = snap.paths.common / "lib" / "nova" / "instances"
        return validate_instances_mount(instances_path)


nova_compute = partial(entry_point, NovaComputeService)


class NovaAPIMetadataService(OpenStackService):
    """A service object used to run the Nova metadata HAProxy bridge."""

    def run(self, snap: Snap) -> int:
        """Runs the local Nova metadata reverse proxy."""
        setup_logging(snap.paths.common / "nova-api-metadata-service.log")

        upstream_url = snap.config.get("network.nova-metadata-proxy-url")
        if not upstream_url or upstream_url == "UNSET":
            logging.error("network.nova-metadata-proxy-url is not configured")
            return 1

        cmd = [
            str(snap.paths.snap / "usr" / "sbin" / "haproxy"),
            "-f",
            str(snap.paths.common / "etc" / "haproxy" / "nova_metadata.cfg"),
            "-db",
        ]
        completed_process = subprocess.run(cmd)

        logging.info("Exiting with code %s", completed_process.returncode)
        return completed_process.returncode


nova_api_metadata = partial(entry_point, NovaAPIMetadataService)


class NeutronOVNAgentService(OpenStackService):
    """A service object used to run the neutron-ovn-agent daemon."""

    conf_files = [
        Path("etc/neutron/neutron.conf"),
        Path("etc/neutron/neutron_ovn_agent.ini"),
    ]
    conf_dirs = [
        Path("etc/neutron/neutron.conf.d"),
    ]

    executable = Path("usr/bin/neutron-ovn-agent")

    def run(self, snap: Snap) -> int:
        """Run neutron-ovn-agent once required connections and local OVS are ready."""
        setup_logging(snap.paths.common / f"{self.executable.name}-{snap.name}.log")
        ovsdb_connections = self._ovsdb_connections(snap)
        if ovsdb_connections is None:
            return 1

        ovsdb_connection = ovsdb_connections["ovsdb_connection"]
        if not self._wait_for_ovsdb_schema(snap, ovsdb_connection):
            return 1

        return super().run(snap)

    def _ovsdb_connections(self, snap: Snap) -> dict[str, str] | None:
        """Read all connections required by the OVN agent."""
        config_path = snap.paths.common / "etc/neutron/neutron_ovn_agent.ini"
        parser = configparser.ConfigParser()
        try:
            if not parser.read(config_path):
                logging.error("Unable to read OVN agent config: %s", config_path)
                return None
            connections = {
                "ovsdb_connection": parser.get("ovs", "ovsdb_connection", fallback="").strip(),
                "ovn_nb_connection": parser.get("ovn", "ovn_nb_connection", fallback="").strip(),
                "ovn_sb_connection": parser.get("ovn", "ovn_sb_connection", fallback="").strip(),
            }
        except (configparser.Error, OSError, UnicodeError):
            logging.error("Unable to parse OVN agent config: %s", config_path)
            return None

        if not all(connections.values()):
            logging.error("Required OVSDB connections are not configured in %s", config_path)
            return None
        return connections

    def _wait_for_ovsdb_schema(self, snap: Snap, ovsdb_connection: str) -> bool:
        """Wait until ovsdb-client can retrieve the Open_vSwitch schema."""
        deadline = time.monotonic() + OVSDB_SCHEMA_TIMEOUT
        socket_path = self._unix_socket_path(ovsdb_connection)
        command = [
            str(snap.paths.snap / "usr" / "bin" / "ovsdb-client"),
            "get-schema",
            ovsdb_connection,
            "Open_vSwitch",
        ]

        while True:
            if socket_path and not socket_path.exists():
                logging.info("Waiting for the local MicroOVN OVSDB socket")
            elif self._ovsdb_schema_available(command):
                return True

            if time.monotonic() >= deadline:
                logging.error("Timed out waiting for the local Open_vSwitch schema")
                return False
            time.sleep(OVSDB_SCHEMA_CHECK_INTERVAL)

    def _ovsdb_schema_available(self, command: list[str]) -> bool:
        """Return whether the OVSDB Open_vSwitch schema is reachable."""
        try:
            completed_process = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            logging.info("Unable to query MicroOVN OVSDB schema yet: %s", exc)
            return False
        return completed_process.returncode == 0

    def _unix_socket_path(self, ovsdb_connection: str) -> Path | None:
        """Return the socket path for unix OVSDB connections."""
        if not ovsdb_connection.startswith("unix:"):
            return None
        return Path(ovsdb_connection.removeprefix("unix:"))


neutron_ovn_agent = partial(entry_point, NeutronOVNAgentService)


class NeutronSRIOVNicAgentService(OpenStackService):
    """A python service object used to run the neutron-sriov-nic-agent daemon."""

    conf_files = [
        Path("etc/neutron/neutron.conf"),
        Path("etc/neutron/neutron_sriov_nic_agent.ini"),
    ]
    conf_dirs = [
        Path("etc/neutron/neutron.conf.d"),
    ]

    executable = Path("usr/bin/neutron-sriov-nic-agent")


neutron_sriov_nic_agent = partial(entry_point, NeutronSRIOVNicAgentService)


class CeilometerComputeAgentService(OpenStackService):
    """A python service object used to run the ceilometer-agent-compute daemon."""

    conf_files = [
        Path("etc/ceilometer/ceilometer.conf"),
    ]
    conf_dirs = []
    extra_args = ["--polling-namespaces", "compute"]

    executable = Path("usr/bin/ceilometer-polling")


ceilometer_compute_agent = partial(entry_point, CeilometerComputeAgentService)


class MasakariInstanceMonitorService(OpenStackService):
    """A python service object used to run the masakari-instancemonitor daemon."""

    conf_files = [
        Path("etc/masakarimonitors/masakarimonitors.conf"),
    ]
    conf_dirs = []
    extra_args = []

    executable = Path("usr/bin/masakari-instancemonitor")


masakari_instancemonitor = partial(entry_point, MasakariInstanceMonitorService)


class PreEvacuationSetupService(OpenStackService):
    """A python service object used to run the pre-evacuation-setup daemon."""

    conf_files = []
    conf_dirs = []
    extra_args = []

    executable = Path("usr/bin/pre-evacuation-setup-service")


pre_evacuation_setup = partial(entry_point, PreEvacuationSetupService)


class FileTransferService:
    """A python service object used to run the Apache WebDAV file transfer service."""

    def run(self, snap: Snap) -> int:
        """Runs the Apache WebDAV file transfer service.

        Starts Apache with mTLS WebDAV for Nova live-migration file transfers.
        TLS material is loaded into anonymous memfds (FDs 3-5) so Apache
        inherits them via /proc/self/fd/{3,4,5} without ever holding a
        filesystem path to the key.  The config is opened directly as FD 6.

        :param snap: the snap context
        :type snap: Snap
        :return: exit code of the process
        :rtype: int
        """
        setup_logging(snap.paths.common / "file-transfer-service.log")

        config_file = snap.paths.common / "etc" / "apache2" / "webdav.conf"
        # TLS material is decoded directly from snap config and written into
        # anonymous memfds. No filesystem path to the key is ever visible in
        # /proc/self/fd/N that Apache uses.
        tls_sources = [
            (3, "cert", "compute.cert"),
            (4, "key", "compute.key"),
            (5, "ca", "compute.cacert"),
        ]

        try:
            # FDs 3-5: decode TLS from snap config, write into anonymous memfds.
            for target_fd, label, config_key in tls_sources:
                try:
                    data = base64.b64decode(snap.config.get(config_key))
                except (binascii.Error, TypeError, UnknownConfigKey):
                    logging.error("TLS %s not configured or invalid (%s)", label, config_key)
                    return 1
                fd = os.memfd_create(label)
                os.write(fd, data)
                os.lseek(fd, 0, os.SEEK_SET)
                if fd != target_fd:
                    os.dup2(fd, target_fd)
                    os.close(fd)
                os.set_inheritable(target_fd, True)

            # FD 6: config file (root:root 0o644, readable without DAC_OVERRIDE).
            try:
                fd = os.open(str(config_file), os.O_RDONLY)
            except OSError as e:
                logging.error("Cannot open config (%s): %s", config_file, e)
                return 1
            if fd != 6:
                os.dup2(fd, 6)
                os.close(fd)
            os.set_inheritable(6, True)

            run_dir = snap.paths.common / "run" / "apache2"
            log_dir = snap.paths.common / "log" / "apache2"

            env = os.environ.copy()
            env.update(
                {
                    "APACHE_RUN_DIR": str(run_dir),
                    "APACHE_LOG_DIR": str(log_dir),
                    "APACHE_PID_FILE": str(run_dir / "apache2.pid"),
                    "APACHE_LOCK_DIR": str(run_dir),
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                }
            )

            apache_bin = snap.paths.snap / "usr" / "sbin" / "apache2"
            cmd = [
                "/usr/bin/setpriv",
                "--reuid",
                "snap_daemon",
                "--regid",
                "snap_daemon",
                "--clear-groups",
                "--inh-caps=-all",
                "--no-new-privs",
                "--",
                str(apache_bin),
                "-e",
                "info",
                "-f",
                "/proc/self/fd/6",
                "-DFOREGROUND",
            ]

            completed_process = subprocess.run(
                cmd,
                env=env,
                pass_fds=(3, 4, 5, 6),
            )

            logging.info(f"Exiting with code {completed_process.returncode}")
            return completed_process.returncode
        except Exception:
            logging.exception("Failed to start file transfer service")
            return 1


file_transfer = partial(entry_point, FileTransferService)
