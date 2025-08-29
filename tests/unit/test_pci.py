# SPDX-FileCopyrightText: 2022 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

from unittest import mock

import pytest

from openstack_hypervisor import pci


class TestPCIUtils:
    """Contains tests for the PCI utils."""

    @pytest.mark.parametrize(
        "device_specs, excluded_devices, pci_device_list, expected_result",
        [
            # Multiple PFs match the device spec, one of them is in the exclusion list.
            (
                [
                    # Matches excluded devices, will be converted to a granular set of
                    # device specs.
                    {
                        "vendor_id": "8086",
                        "product_id": "1563",
                        "physical_network": "physnet1",
                    },
                    # Does not match excluded devices, will be passed as-is.
                    {
                        "vendor_id": "15b3",
                        "product_id": "1007",
                        "physical_network": "physnet2",
                    },
                ],
                ["0000:1b:00.1"],
                [
                    {
                        "vendor_id": "8086",
                        "product_id": "1563",
                        "address": "0000:19:00.0",
                        "physfn_address": "",
                    },
                    {
                        "vendor_id": "8086",
                        "product_id": "1563",
                        "address": "0000:19:00.1",
                        "physfn_address": "",
                    },
                    {
                        "vendor_id": "8086",
                        "product_id": "1563",
                        "address": "0000:1b:00.0",
                        "physfn_address": "",
                    },
                    {
                        "vendor_id": "8086",
                        "product_id": "1563",
                        "address": "0000:1b:00.1",
                        "physfn_address": "",
                    },
                    {
                        "vendor_id": "15b3",
                        "product_id": "1007",
                        "address": "0000:5e:00.0",
                        "physfn_address": "",
                    },
                ],
                [
                    {
                        "vendor_id": "8086",
                        "product_id": "1563",
                        "address": "0000:19:00.0",
                        "physical_network": "physnet1",
                    },
                    {
                        "vendor_id": "8086",
                        "product_id": "1563",
                        "address": "0000:19:00.1",
                        "physical_network": "physnet1",
                    },
                    {
                        "vendor_id": "8086",
                        "product_id": "1563",
                        "address": "0000:1b:00.0",
                        "physical_network": "physnet1",
                    },
                    {
                        "vendor_id": "15b3",
                        "product_id": "1007",
                        "physical_network": "physnet2",
                    },
                ],
            ),
        ],
    )
    def test_apply_exclusion_list(
        self,
        device_specs: list[dict],
        excluded_devices: list[str],
        pci_device_list: list[dict],
        expected_result,
    ):
        with mock.patch.object(pci, "list_pci_devices") as mock_list_devices:
            mock_list_devices.return_value = pci_device_list
            result = pci.apply_exclusion_list(device_specs, excluded_devices)

        assert expected_result == result

    def test_set_driver_override(self, check_call):
        pci.set_driver_override("pci-address", "driver-name")

        check_call.assert_called_once_with(
            ["driverctl", "set-override", "pci-address", "driver-name"]
        )

    def test_get_driver_overrides(self, check_output):
        check_output.return_value = b"0000:1a:00.0 (none)\n0000:1a:00.1 vfio-pci\n"

        overrides = pci.get_driver_overrides()
        expected_overrides = {
            "0000:1a:00.1": "vfio-pci",
        }
        assert expected_overrides == overrides

        check_output.assert_called_once_with(
            ["driverctl", "list-overrides"],
        )

    @mock.patch.object(pci, "set_driver_override")
    @mock.patch.object(pci, "get_driver_overrides")
    def test_ensure_driver_override(self, mock_get_driver_overrides, mock_set_driver_override):
        mock_get_driver_overrides.return_value = {
            "0000:1a:00.0": "ixgbe",
            "0000:1a:00.1": "vfio-pci",
        }

        pci.ensure_driver_override("0000:1a:00.0", "vfio-pci")
        pci.ensure_driver_override("0000:1a:00.1", "vfio-pci")

        mock_set_driver_override.assert_called_once_with("0000:1a:00.0", "vfio-pci")
