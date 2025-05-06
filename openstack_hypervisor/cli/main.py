# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import click

from openstack_hypervisor.cli.hypervisor import hypervisor
from openstack_hypervisor.cli.interfaces import list_nics
from openstack_hypervisor.cli.log import setup_root_logging

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


@click.group("init", context_settings=CONTEXT_SETTINGS)
@click.option("-v", "--verbose", is_flag=True, help="Increase output verbosity")
def cli(verbose: bool):
    """Set of utilities for managing the hypervisor."""


def main():
    """Register commands and run the CLI."""
    setup_root_logging()
    cli.add_command(list_nics)
    cli.add_command(hypervisor)

    cli()


if __name__ == "__main__":
    main()
