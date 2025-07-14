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
