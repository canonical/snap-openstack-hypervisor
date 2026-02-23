# SPDX-FileCopyrightText: 2022 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import base64
import binascii
import logging
import os
import subprocess
import sys
from functools import partial
from pathlib import Path

from snaphelpers import Snap, UnknownConfigKey

from openstack_hypervisor.log import setup_logging


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


class NovaComputeService(OpenStackService):
    """A python service object used to run the nova-compute daemon."""

    conf_files = [
        Path("etc/nova/nova.conf"),
    ]
    conf_dirs = [
        Path("etc/nova/nova.conf.d"),
    ]

    executable = Path("usr/bin/nova-compute")


nova_compute = partial(entry_point, NovaComputeService)


class NovaAPIMetadataService(OpenStackService):
    """A python service object used to run the nova-api-metadata daemon."""

    conf_files = [
        Path("etc/nova/nova.conf"),
    ]
    conf_dirs = [
        Path("etc/nova/nova.conf.d"),
    ]

    executable = Path("usr/bin/nova-api-metadata")


nova_api_metadata = partial(entry_point, NovaAPIMetadataService)


class NeutronOVNMetadataAgentService(OpenStackService):
    """A python service object used to run the neutron-ovn-metadata-agent daemon."""

    conf_files = [
        Path("etc/neutron/neutron.conf"),
        Path("etc/neutron/neutron_ovn_metadata_agent.ini"),
    ]
    conf_dirs = [
        Path("etc/neutron/neutron.conf.d"),
    ]

    executable = Path("usr/bin/neutron-ovn-metadata-agent")


neutron_ovn_metadata_agent = partial(entry_point, NeutronOVNMetadataAgentService)


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


class OVSDBServerService:
    """A python service object used to run the ovsdb-server daemon."""

    def run(self, snap: Snap) -> int:
        """Runs the ovsdb-server service.

        Invoked when this service is started.

        :param snap: the snap context
        :type snap: Snap
        :return: exit code of the process
        :rtype: int
        """
        setup_logging(snap.paths.common / f"ovsdb-server-{snap.name}.log")

        executable = snap.paths.snap / "usr" / "share" / "openvswitch" / "scripts" / "ovs-ctl"
        args = [
            "--no-ovs-vswitchd",
            "--no-monitor",
            f"--system-id={snap.config.get('node.fqdn')}",
            "start",
        ]
        cmd = [str(executable)]
        cmd.extend(args)

        completed_process = subprocess.run(cmd)

        logging.info(f"Exiting with code {completed_process.returncode}")
        return completed_process.returncode


ovsdb_server = partial(entry_point, OVSDBServerService)


class OVSExporterService:
    """A python service object used to run the ovs-exporter daemon."""

    def run(self, snap: Snap) -> int:
        """Runs the ovs-exporter service.

        Invoked when config monitoring is enable.

        :param snap: the snap context
        :type snap: Snap
        :return: exit code of the process
        :rtype: int
        """
        setup_logging(snap.paths.common / "ovs-exporter.log")
        executable = snap.paths.snap / "bin" / "ovs-exporter"
        listen_address = ":9475"
        args = [
            f"-web.listen-address={listen_address}",
            "-database.vswitch.file.data.path",
            f"{snap.paths.common}/etc/openvswitch/conf.db",
            "-database.vswitch.file.log.path",
            f"{snap.paths.common}/log/openvswitch/ovsdb-server.log",
            "-database.vswitch.file.pid.path",
            f"{snap.paths.common}/run/openvswitch/ovsdb-server.pid",
            "-database.vswitch.file.system.id.path",
            f"{snap.paths.common}/etc/openvswitch/system-id.conf",
            "-database.vswitch.name",
            "Open_vSwitch",
            "-database.vswitch.socket.remote",
            "unix:" + f"{snap.paths.common}/run/openvswitch/db.sock",
            "-service.ovncontroller.file.log.path",
            f"{snap.paths.common}/log/ovn/ovn-controller.log",
            "-service.ovncontroller.file.pid.path",
            f"{snap.paths.common}/run/ovn/ovn-controller.pid",
            "-service.vswitchd.file.log.path",
            f"{snap.paths.common}/log/openvswitch/ovs-vswitchd.log",
            "-service.vswitchd.file.pid.path",
            f"{snap.paths.common}/run/openvswitch/ovs-vswitchd.pid",
            "-system.run.dir",
            f"{snap.paths.common}/run/openvswitch",
        ]
        cmd = [str(executable)]
        cmd.extend(args)

        completed_process = subprocess.run(cmd)

        logging.info(f"Exiting with code {completed_process.returncode}")
        return completed_process.returncode


ovs_exporter = partial(entry_point, OVSExporterService)


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
