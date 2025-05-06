# SPDX-FileCopyrightText: 2023 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import time
import xml.etree.ElementTree

import libvirt


def openstack_guest(guest_xml: str) -> bool:
    """Check if guest is managed by OpenStack."""
    ns = {"nova": "http://openstack.org/xmlns/libvirt/nova/1.1"}
    root = xml.etree.ElementTree.fromstring(guest_xml)
    metadata = root.findall("metadata")
    return bool([e.findall("nova:instance", ns) for e in metadata])


def guest_uuid(guest_xml: str) -> str:
    """Extract guest UUID from XML."""
    root = xml.etree.ElementTree.fromstring(guest_xml)
    return root.find("uuid").text


def all_guests() -> list:
    """List all guests."""
    conn = libvirt.open("qemu:///system")
    return conn.listAllDomains()


def running_guests(guests) -> list:
    """Extract list of running domains from provided list."""
    running = [dom for dom in guests if dom.isActive()]
    return running


def delete_openstack_guests() -> None:
    """Delete any guests managed by openstack."""
    openstack_guests = [dom for dom in all_guests() if openstack_guest(dom.XMLDesc())]
    for dom in running_guests(openstack_guests):
        try:
            dom.destroy()
        except libvirt.libvirtError as e:
            if "domain is not running" in e.get_error_message():
                pass
            else:
                raise

    for i in range(0, 150):
        if not running_guests(openstack_guests):
            break
        time.sleep(0.2)
    else:
        raise TimeoutError("Some guests not shutdown")
    for dom in openstack_guests:
        dom.undefine()
