# Contributing

## Overview

This document explains the processes and practices recommended for contributing enhancements to the OpenStack Hypervisor snap.

- Before contributing, you should consider [opening an issue](https://github.com/canonical/snap-openstack-hypervisor/issues) explaining your use case.
- If you would like to chat with us about your use-cases or proposed implementation, you can reach us at the [OpenStack Sunbeam community chat](https://matrix.to/#/#openstack-sunbeam:ubuntu.com).
- Familiarize yourself with [Snaps and Snapcraft](https://snapcraft.io/docs) documentation will help you a lot when working on new features or bug fixes.
- All enhancements require review before being merged. Code review typically examines
  - code quality
  - test coverage
- Please help us out in ensuring easy to review branches by rebasing your pull request branch onto the `main` branch. This also avoids merge commits and creates a linear Git commit history.

## Reporting a bug

Please report bugs to the [OpenStack Snap](https://bugs.launchpad.net/snap-openstack-hypervisor) project on Launchpad.

## Developing

The project uses [uv](https://docs.astral.sh/uv/) for dependency management. Create and activate a development environment with the dev extras:

```shell
uv sync --extra dev
source .venv/bin/activate
```

### Testing

```shell
tox -e fmt           # format your code (isort + black)
tox -e lint          # code style (flake8, isort, black, codespell)
tox -e unit          # unit tests
tox                  # runs 'lint' and 'unit' environments
```

## Build Snap

Build the snap in this git repository using:

```shell
snapcraft --use-lxd
```

### Deploy a locally built snap

For testing a local change, you may wish to build and deploy the snap yourself. Install the locally built snap in dangerous mode (required because it is an unsigned package):

```bash
sudo snap install --dangerous openstack-hypervisor_*.snap
```

Alternatively, use [`snap try`](https://snapcraft.io/docs/snap-try) to install from an unpacked directory, which is useful if you want to make further changes and test them without rebuilding the snap:

```bash
unsquashfs openstack-hypervisor_*.snap
sudo snap try ./squashfs-root
```

Configure the snap with credentials and URLs for the OpenStack cloud it will form part of:

```bash
# Identity service (Keystone)
sudo snap set openstack-hypervisor \
    identity.auth-url=http://10.64.140.43:80/sunbeam-keystone \
    identity.username=nova-hypervisor-01 \
    identity.password=supersecure21

# RabbitMQ
sudo snap set openstack-hypervisor \
    rabbitmq.url=rabbit://nova:supersecure22@10.152.183.212:5672/openstack

# Network services (OVN)
sudo snap set openstack-hypervisor \
    network.ovn-sb-connection=tcp:10.152.183.220:6642

# Restart the services for the changes to take effect
sudo snap restart openstack-hypervisor
```

See the [Configuration Reference](README.md#configuration-reference) section of the README for the full set of configuration options.

## Canonical Contributor Agreement

Canonical welcomes contributions to the OpenStack Hypervisor snap. Please check out our [contributor agreement](https://ubuntu.com/legal/contributors) if you're interested in contributing to the solution.
