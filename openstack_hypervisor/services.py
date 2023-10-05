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

import logging
import subprocess
import sys
from functools import partial
from pathlib import Path

from snaphelpers import Snap

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


class CeilometerComputeAgentService(OpenStackService):
    """A python service object used to run the ceilometer-agent-compute daemon."""

    conf_files = [
        Path("etc/ceilometer/ceilometer.conf"),
    ]
    conf_dirs = []
    extra_args = ["--polling-namespaces", "compute"]

    executable = Path("usr/bin/ceilometer-polling")


ceilometer_compute_agent = partial(entry_point, CeilometerComputeAgentService)


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
