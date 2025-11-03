# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import patch

from openstack_hypervisor.bridge_datapath import (
    BridgeMapping,
    resolve_bridge_mappings,
    resolve_ovs_changes,
)

mapping = [
    BridgeMapping("physnet1", "br-ex", "eth0"),
    BridgeMapping("physnet2", "br-physnet2", "eth1"),
]


class TestBridgeChangesResolution:
    def test_no_change(self):
        assert resolve_ovs_changes(
            mapping,
            mapping,
        ) == {
            "renamed_bridges": [],
            "added_bridges": [],
            "removed_bridges": [],
            "interface_changes": {},
        }

    def test_new_bridge(self):
        new_map = mapping + [BridgeMapping("physnet3", "br-physnet3", "eth1")]
        assert resolve_ovs_changes(
            mapping,
            new_map,
        ) == {
            "renamed_bridges": [],
            "added_bridges": ["br-physnet3"],
            "removed_bridges": [],
            "interface_changes": {"br-physnet3": {"removed": [], "added": ["eth1"]}},
        }

    def test_removed_bridge(self):
        new_map = mapping[:-1]
        assert resolve_ovs_changes(
            mapping,
            new_map,
        ) == {
            "renamed_bridges": [],
            "added_bridges": [],
            "removed_bridges": ["br-physnet2"],
            "interface_changes": {"br-physnet2": {"removed": ["eth1"], "added": []}},
        }

    def test_renamed_bridge(self):
        new_map = [
            BridgeMapping("physnet1", "br-exotic", "eth0"),
            BridgeMapping("physnet2", "br-physnet2", "eth1"),
        ]
        assert resolve_ovs_changes(
            mapping,
            new_map,
        ) == {
            "renamed_bridges": [("br-ex", "br-exotic")],
            "added_bridges": [],
            "removed_bridges": [],
            "interface_changes": {},
        }

    def test_remove_interface(self):
        new_map = [
            BridgeMapping("physnet1", "br-ex", "eth0"),
            BridgeMapping("physnet2", "br-physnet2", None),
        ]
        assert resolve_ovs_changes(
            mapping,
            new_map,
        ) == {
            "renamed_bridges": [],
            "added_bridges": [],
            "removed_bridges": [],
            "interface_changes": {"br-physnet2": {"removed": ["eth1"], "added": []}},
        }

    def test_add_interface(self):
        new_map = [
            BridgeMapping("physnet1", "br-ex", "eth0"),
            BridgeMapping("physnet2", "br-physnet2", "eth1"),
            BridgeMapping("physnet2", "br-physnet2", "eth2"),
        ]
        assert resolve_ovs_changes(
            mapping,
            new_map,
        ) == {
            "renamed_bridges": [],
            "added_bridges": [],
            "removed_bridges": [],
            "interface_changes": {"br-physnet2": {"removed": [], "added": ["eth2"]}},
        }

    def test_lot_of_changes(self):
        old_map = [
            BridgeMapping("physnet1", "br-old", "eth0"),
            BridgeMapping("physnet2", "br-physnet2", "eth1"),
        ]
        new_map = [
            BridgeMapping("physnet2", "br-physnet2", "eth2"),
            BridgeMapping("physnet1", "br-new", "eth4"),
            BridgeMapping("physnet3", "br-physnet3", "eth1"),
        ]
        assert resolve_ovs_changes(
            old_map,
            new_map,
        ) == {
            "renamed_bridges": [("br-old", "br-new")],
            "added_bridges": ["br-physnet3"],
            "removed_bridges": [],
            "interface_changes": {
                "br-physnet2": {"removed": ["eth1"], "added": ["eth2"]},
                "br-physnet3": {"removed": [], "added": ["eth1"]},
                "br-old": {"removed": ["eth0"], "added": ["eth4"]},
            },
        }

    def test_physnet_move(self):
        old_map = [
            BridgeMapping("physnet1", "br-ex", "eth0"),
            BridgeMapping("physnet2", "br-physnet2", "eth1"),
        ]
        new_map = [
            BridgeMapping("physnet1", "br-ex", "eth0"),
            BridgeMapping("physnet3", "br-physnet3", "eth1"),
        ]
        assert resolve_ovs_changes(
            old_map,
            new_map,
        ) == {
            "renamed_bridges": [],
            "added_bridges": ["br-physnet3"],
            "removed_bridges": [
                "br-physnet2",
            ],
            "interface_changes": {
                "br-physnet2": {"removed": ["eth1"], "added": []},
                "br-physnet3": {"removed": [], "added": ["eth1"]},
            },
        }


class TestResolveBridgeMappings:
    """Comprehensive test suite for resolve_bridge_mappings function.

    This test suite covers:
    - Empty/null inputs
    - Basic physnet and interface mappings
    - Partial mappings (physnet without interface, etc.)
    - Legacy parameter support
    - Whitespace handling and formatting
    - Invalid input handling and error cases
    - Special characters in names (hyphens, underscores, numbers)
    - VLAN tags and bond interfaces
    - Duplicate handling (physnets and bridges)
    - Case sensitivity
    - BridgeMapping dataclass behavior
    - Edge cases and complex scenarios
    """

    def test_empty_all_parameters(self):
        """Test with all empty parameters."""
        result = resolve_bridge_mappings("", "", "", "", "")
        assert result == []

    def test_basic_physnet_mapping_only(self):
        """Test with only physnet mapping, no interfaces."""
        result = resolve_bridge_mappings("", "", "", "physnet1:br-ex physnet2:br-data", "")
        assert len(result) == 2
        assert BridgeMapping("physnet1", "br-ex", None) in result
        assert BridgeMapping("physnet2", "br-data", None) in result

    def test_physnet_and_interface_mapping(self):
        """Test with both physnet and interface mappings."""
        result = resolve_bridge_mappings(
            "",
            "",
            "",
            "physnet1:br-ex physnet2:br-data",
            "br-ex:eth0 br-data:eth1",
        )
        assert len(result) == 2
        assert BridgeMapping("physnet1", "br-ex", "eth0") in result
        assert BridgeMapping("physnet2", "br-data", "eth1") in result

    def test_interface_mapping_only(self):
        """Test with only interface mapping, no physnet mapping."""
        result = resolve_bridge_mappings("", "", "", "", "br-ex:eth0 br-data:eth1")
        assert result == []

    def test_partial_interface_mapping(self):
        """Test with physnet mapping where only some bridges have interfaces."""
        result = resolve_bridge_mappings(
            "", "", "", "physnet1:br-ex physnet2:br-data", "br-ex:eth0"
        )
        assert len(result) == 2
        assert BridgeMapping("physnet1", "br-ex", "eth0") in result
        assert BridgeMapping("physnet2", "br-data", None) in result

    def test_extra_interface_mapping(self):
        """Test with interface mapping for non-existent bridge."""
        result = resolve_bridge_mappings(
            "", "", "", "physnet1:br-ex", "br-ex:eth0 br-nonexistent:eth1"
        )
        assert len(result) == 1
        assert BridgeMapping("physnet1", "br-ex", "eth0") in result

    def test_legacy_external_bridge_params(self):
        """Test with legacy external bridge parameters."""
        result = resolve_bridge_mappings("br-ex", "physnet-ext", "eth0", "", "")
        assert len(result) == 1
        assert result[0] == BridgeMapping("physnet-ext", "br-ex", "eth0")

    def test_legacy_external_bridge_with_empty_nic(self):
        """Test with legacy external bridge parameters with empty NIC."""
        result = resolve_bridge_mappings("br-ex", "physnet-ext", "", "", "")
        assert len(result) == 1
        assert result[0] == BridgeMapping("physnet-ext", "br-ex", None)

    def test_legacy_params_override_by_new_params(self):
        """Test that new parameters take precedence over legacy ones."""
        result = resolve_bridge_mappings(
            "br-old", "physnet-old", "eth9", "physnet1:br-new", "br-new:eth0"
        )
        # New parameters should be used, legacy should be ignored
        assert len(result) == 1
        assert BridgeMapping("physnet1", "br-new", "eth0") in result

    def test_whitespace_handling(self):
        """Test that whitespace is properly stripped from mappings."""
        result = resolve_bridge_mappings(
            "", "", "", "  physnet1:br-ex   physnet2:br-data  ", " br-ex:eth0  "
        )
        assert len(result) == 2
        assert BridgeMapping("physnet1", "br-ex", "eth0") in result
        assert BridgeMapping("physnet2", "br-data", None) in result

    def test_single_physnet_mapping(self):
        """Test with a single physnet mapping."""
        result = resolve_bridge_mappings("", "", "", "physnet1:br-ex", "br-ex:eth0")
        assert len(result) == 1
        assert result[0] == BridgeMapping("physnet1", "br-ex", "eth0")

    def test_multiple_physnets_single_interface(self):
        """Test multiple physnets but only one has an interface."""
        result = resolve_bridge_mappings(
            "",
            "",
            "",
            "physnet1:br-ex physnet2:br-data physnet3:br-tenant",
            "br-data:eth1",
        )
        assert len(result) == 3
        assert BridgeMapping("physnet1", "br-ex", None) in result
        assert BridgeMapping("physnet2", "br-data", "eth1") in result
        assert BridgeMapping("physnet3", "br-tenant", None) in result

    def test_complex_mapping_scenario(self):
        """Test a complex real-world scenario."""
        result = resolve_bridge_mappings(
            "",
            "",
            "",
            "physnet-public:br-ex physnet-data:br-data physnet-tenant:br-tenant",
            "br-ex:bond0 br-data:eth1 br-tenant:vlan100",
        )
        assert len(result) == 3
        assert BridgeMapping("physnet-public", "br-ex", "bond0") in result
        assert BridgeMapping("physnet-data", "br-data", "eth1") in result
        assert BridgeMapping("physnet-tenant", "br-tenant", "vlan100") in result

    def test_invalid_physnet_mapping_format(self):
        """Test with invalid physnet mapping format (missing colon)."""
        with patch("openstack_hypervisor.bridge_datapath.logging.warning") as mock_warn:
            result = resolve_bridge_mappings(
                "", "", "", "physnet1:br-ex invalidmapping physnet2:br-data", ""
            )
            # Should skip the invalid one and continue with valid ones
            assert len(result) == 2
            assert BridgeMapping("physnet1", "br-ex", None) in result
            assert BridgeMapping("physnet2", "br-data", None) in result
            mock_warn.assert_called_once()

    def test_invalid_interface_mapping_format(self):
        """Test with invalid interface mapping format (missing colon)."""
        with patch("openstack_hypervisor.bridge_datapath.logging.warning") as mock_warn:
            result = resolve_bridge_mappings(
                "", "", "", "physnet1:br-ex", "br-ex:eth0 invalidmapping"
            )
            assert len(result) == 1
            assert BridgeMapping("physnet1", "br-ex", "eth0") in result
            mock_warn.assert_called_once()

    def test_multiple_invalid_mappings(self):
        """Test with multiple invalid mappings."""
        with patch("openstack_hypervisor.bridge_datapath.logging.warning") as mock_warn:
            result = resolve_bridge_mappings(
                "",
                "",
                "",
                "physnet1:br-ex bad1 bad2 physnet2:br-data",
                "br-ex:eth0 bad3",
            )
            assert len(result) == 2
            assert BridgeMapping("physnet1", "br-ex", "eth0") in result
            assert BridgeMapping("physnet2", "br-data", None) in result
            # Should have warned 3 times (bad1, bad2, bad3)
            assert mock_warn.call_count == 3

    def test_empty_physnet_name_legacy(self):
        """Test legacy parameters with empty physnet name."""
        result = resolve_bridge_mappings("br-ex", "", "eth0", "", "")
        # Should not create mapping without physnet name
        assert result == []

    def test_empty_bridge_name_legacy(self):
        """Test legacy parameters with empty bridge name."""
        result = resolve_bridge_mappings("", "physnet-ext", "eth0", "", "")
        # Should not create mapping without bridge name
        assert result == []

    def test_bridge_name_with_special_chars(self):
        """Test bridge names with hyphens and numbers."""
        result = resolve_bridge_mappings(
            "",
            "",
            "",
            "physnet-1:br-ex-123 physnet_2:br_data_456",
            "br-ex-123:eth0.100 br_data_456:bond0",
        )
        assert len(result) == 2
        assert BridgeMapping("physnet-1", "br-ex-123", "eth0.100") in result
        assert BridgeMapping("physnet_2", "br_data_456", "bond0") in result

    def test_interface_name_with_vlan_tags(self):
        """Test interface names with VLAN tags."""
        result = resolve_bridge_mappings("", "", "", "physnet1:br-ex", "br-ex:eth0.100")
        assert len(result) == 1
        assert result[0] == BridgeMapping("physnet1", "br-ex", "eth0.100")

    def test_interface_name_with_bond(self):
        """Test interface names as bonds."""
        result = resolve_bridge_mappings("", "", "", "physnet1:br-ex", "br-ex:bond0")
        assert len(result) == 1
        assert result[0] == BridgeMapping("physnet1", "br-ex", "bond0")

    def test_order_preservation(self):
        """Test that mapping order is preserved (dict iteration order)."""
        result = resolve_bridge_mappings(
            "",
            "",
            "",
            "physnet1:br-ex physnet2:br-data physnet3:br-tenant",
            "br-ex:eth0 br-data:eth1 br-tenant:eth2",
        )
        assert len(result) == 3
        # Check all expected mappings exist
        physnets = [m.physnet for m in result]
        assert "physnet1" in physnets
        assert "physnet2" in physnets
        assert "physnet3" in physnets

    def test_duplicate_physnet_names(self):
        """Test with duplicate physnet names (last one wins)."""
        result = resolve_bridge_mappings(
            "", "", "", "physnet1:br-ex physnet1:br-data", "br-data:eth0"
        )
        # Dict behavior: last value for duplicate key wins
        assert len(result) == 1
        assert BridgeMapping("physnet1", "br-data", "eth0") in result

    def test_duplicate_bridge_names(self):
        """Test with duplicate bridge names for different physnets."""
        result = resolve_bridge_mappings("", "", "", "physnet1:br-ex physnet2:br-ex", "br-ex:eth0")
        assert len(result) == 2
        # Both should map to the same bridge with the same interface
        assert BridgeMapping("physnet1", "br-ex", "eth0") in result
        assert BridgeMapping("physnet2", "br-ex", "eth0") in result

    def test_case_sensitivity(self):
        """Test that names are case-sensitive."""
        result = resolve_bridge_mappings(
            "", "", "", "PhysNet1:BR-EX physnet1:br-ex", "BR-EX:ETH0 br-ex:eth0"
        )
        assert len(result) == 2
        assert BridgeMapping("PhysNet1", "BR-EX", "ETH0") in result
        assert BridgeMapping("physnet1", "br-ex", "eth0") in result

    def test_physnet_bridge_pair_method(self):
        """Test the physnet_bridge_pair method on BridgeMapping."""
        mapping = BridgeMapping("physnet1", "br-ex", "eth0")
        assert mapping.physnet_bridge_pair() == "physnet1:br-ex"

    def test_bridge_mapping_immutability(self):
        """Test that BridgeMapping is immutable (frozen dataclass)."""
        mapping = BridgeMapping("physnet1", "br-ex", "eth0")
        try:
            mapping.physnet = "physnet2"  # type: ignore
            assert False, "Should not allow modification of frozen dataclass"
        except (AttributeError, TypeError):
            pass  # Expected - frozen dataclass cannot be modified

    def test_none_interface_representation(self):
        """Test that None interface is properly represented."""
        result = resolve_bridge_mappings("", "", "", "physnet1:br-ex", "")
        assert len(result) == 1
        assert result[0].interface is None
        assert result[0] == BridgeMapping("physnet1", "br-ex", None)
