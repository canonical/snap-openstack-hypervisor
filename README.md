# OpenStack Hypervisor Snap

This repository contains the source for the the OpenStack Hypervisor snap.

This snap is designed to be used with a deployed OpenStack Control plane such
as delivered by Sunbeam.

## Getting Started

To get started with the OpenStack Hypervisor, install the snap using snapd:

```bash
$ sudo snap install openstack-hypervisor
```

The snap needs to be configured with credentials and URL's for the Identity
service of the OpenStack cloud that it will form part of - for example:

```bash
$ sudo snap set openstack-hypervisor \
    identity.auth_url=http://10.64.140.43:80/sunbeam-keystone \
    identity.username=nova-hypervisor-01 \
    identity.password=supersecure21
```

it's also possible to configure domain and project configuration.

The snap also needs to be configured with access to RabbitMQ:

```bash
$ sudo snap set openstack-hypervisor \
    rabbitmq.url=rabbit://nova:supersecure22@10.152.183.212:5672/openstack
```

and with URL's for access to Network services:

```bash
$ sudo snap set openstack-hypervisor \
    network.ovn-sb-connection=tcp:10.152.183.220:6642
```

The snap has numerous other configuration options - see "Configuration Reference"
for full details.

## Configuration Reference

### compute

Configuration of options related to compute (Nova):

* `compute.virt-type` libvirt Virtualization type

This option is runtime detected by the snap and will be set
to `kvm` if the host is capable of full virtualization or `qemu` if not.

* `compute.cpu-mode` (`host-model`) CPU mode for instances

Valid values: `host-model`, `host-passthrough`, `custom`, `none`.

* `compute.cpu-models` CPU models for hypervisor

An ordered list of CPU models the host supports.

Only used with `compute.cpu-mode` is set to `custom`.

For more details please refer to the Nova [configuration reference](https://docs.openstack.org/nova/latest/admin/cpu-models.html)
for cpu models.

* `compute.spice-proxy-address` (`localhost`) IP address for SPICE consoles

IP address to use for configuration of SPICE consoles in instances.

* `compute.resume-on-boot` (true) Resume instances on boot

Whether to resume instances on boot or not.

* `compute.flavors` Flavor of the compute host

Comma separated string of Flavors like SEV, SRIOV, DPDK.
Currently SEV is supported for instance memory encryption.

Valid values: `sev`

* `sev.reserved-host-memory-mb` Host memory reserved

Amount of memory reserved for host in MB. nova-compute service deducts this
memory from the available memory in the usage report sent to the placement
service.

* `compute.pci-device-specs` PCI passthrough whitelist

A list of device specs used to set the `pci.device_spec` option in
nova.conf, which allows PCI passthrough of specific devices to VMs.

Example applications: GPU processing, SR-IOV networking, etc.

NOTE: For PCI passthrough to work IOMMU must be enabled on the machine
deployed to. This can be accomplished by setting kernel parameters on
capable machines in MAAS, tagging them and using these tags as
constraints in the model.

* `compute.pci-excluded-devices` PCI excluded devices

A list of PCI addresses that will be excluded from the Nova PCI device whitelist.
The main purpose of this setting is to accommodate per-node exclusion lists.

For example, let's say that the user whitelisted all Intel x550 devices and then
excluded one out of 4 such interfaces:
    pci_device_specs = [{"vendor_id": "8086", "product_id": "1563"}]
    excluded_devices = ["0000:1b:00.1"]

The updated device spec will contain the vendor/product and pci address of the remaining
3 Intel x550 devies.

    [
        {"vendor_id": "8086", "product_id": "1563", "address": "0000:19:00.0"},
        {"vendor_id": "8086", "product_id": "1563", "address": "0000:19:00.1"},
        {"vendor_id": "8086", "product_id": "1563", "address": "0000:1b:00.0"},
    ]

A device spec that doesn't contain any excluded devices will not be modified.

* `compute.pci-aliases` PCI device alias

Sets the `pci-alias` option in nova.conf, defining aliases for assignable
PCI devices that can be requested through flavor extra specs.


### identity

Configuration of options related to identity (Keystone):

* `identity.auth-url` Full URL for Keystone API
* `identity.username` Username for services to use
* `identity.password` Password for services to use
* `identity.user-domain-name` (`service_domain`) Domain for user
* `identity.project-name` (`services`) Service project
* `identity.project-domain-name` (`service_domain`) Domain for service project
* `identity.region-name` (`RegionOne`) OpenStack region to use
* `identity.keystone-region-name` (`RegionOne`) The region of the Keystone service,
  which can be different than `identity.region-name` in multi-region environments.

### logging

Configuration of logging options across all services:

* `logging.debug` (`false`) Enable debug log level

### node

Configuration of options related to the hypervisor node in general:

* `node.fqdn` (`hostname -f`) Fully qualified hostname for node
* `node.ip-address` IP address to use for service configuration

These options are use to configure the identity of the agents that
run as part of the snap.

### network

Configuration of options related to networking, including Neutron
and OVN:

* `network.dns-servers` External DNS servers to use for forwarding DNS requests

* `network.external-bridge` (`br-ex`)  Name of OVS external network bridge (Deprecated)
* `network.physnet-name` (`physnet1`) Neutron label for physical network (Deprecated)
* `network.bridge-mapping` Mapping of bridge to physnet to iface, format:
  `<bridge>:<physnet>[:<interface>] <bridge2>:<physnet2>[:<interface2>]`

* `network.ip-address` (`node.ip-address`) IP address to use for overlay network endpoints
* `network.ovn-sb-connection` (`tcp:127.0.0.1:6642`) OVN Southbound DB connection URL
* `network.enable-gateway` (False) Obsolete - gateway status determined from configuration

TLS configuration for OVN can also be supplied via snap configuration:

* `network.ovn-key` Private TLS key
* `network.ovn-cert` TLS certificate for `ovn-key`
* `network.ovn-cacert` CA certificate (and chain) for certificate validation

All of the above options must be provided as base64 encoded strings.

OVS DPDK settings:

* `network.ovs-dpdk-enabled`: specifies whether ovs should initialize DPDK support
* `network.ovs-memory`: comma separated list of integers that represent the memory (in MB)
  from each NUMA node to be used by OVS for DPDK
* `network.ovs-pmd-cpu-mask` bit mask specifying which CPUs should be used by OVS to run
  the PMD threads. For example, 0xF0 would enable the 5,6,7,8 cores.
* `network.ovs-lcore-mask` bit mask specifying which CPUs should be used by OVS to run
  the lcore threads. For example, 0xF0 would enable the 5,6,7,8 cores.
* `network.ovs-dpdk-ports` comma separated list of interface names that will be used
  with DPDK. The interfaces will be bound to the DPDK-compatible driver (vfio-pci by default)
  and corresponding DPDK ports will be created in OVS. Any bridges and bonds that use
  those interfaces will be updated with the resulting DPDK ports, based on the
  MAAS/Netplan configuration.
* `network.dpdk-driver` The DPDK driver used to control physical network interfaces.
  Possible values: `vfio-pci` (default) or `uio-pci-generic`.

SR-IOV agent settings:

* `network.sriov-nic-exclude-devices`: SR-IOV excluded VFs

Comma-separated list of `<network_device>:<vfs_to_exclude>` tuples, mapping interfaces
to PCI address of excluded SR-IOV VFs, which will not be handled by the SR-IOV agent.

### rabbitmq

Configuration of options related to RabbitMQ messaging:

* `rabbitmq.url` (`rabbit://localhost:5672`) Full connection URL to RabbitMQ

## Build

The build and test with this snap see CONTRIBUTING.md.
