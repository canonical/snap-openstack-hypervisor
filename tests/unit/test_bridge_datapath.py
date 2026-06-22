# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import hashlib
import json
import re
from unittest.mock import patch

import pytest

from openstack_hypervisor.bridge_datapath import (
    DEFAULT_LAA_MAC_PREFIX,
    SB_RENAME_SAFE_QUERY_TIMEOUT_S,
    BridgeMapping,
    OVNCommandError,
    OVNSBCli,
    OVNTimeoutError,
    OVSCli,
    OVSCommandError,
    detect_current_mappings,
    generate_stable_laa_mac,
    is_bridge_rename_safe,
    resolve_bridge_mappings,
    resolve_ovs_changes,
    update_mappings_from_rename,
)

# Note: BridgeMapping field order is (bridge, physnet, interface)
mapping = [
    BridgeMapping("br-ex", "physnet1", "eth0"),
    BridgeMapping("br-physnet2", "physnet2", "eth1"),
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
        new_map = mapping + [BridgeMapping("br-physnet3", "physnet3", "eth1")]
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
            BridgeMapping("br-exotic", "physnet1", "eth0"),
            BridgeMapping("br-physnet2", "physnet2", "eth1"),
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
            BridgeMapping("br-ex", "physnet1", "eth0"),
            BridgeMapping("br-physnet2", "physnet2", None),
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
            BridgeMapping("br-ex", "physnet1", "eth0"),
            BridgeMapping("br-physnet2", "physnet2", "eth1"),
            BridgeMapping("br-physnet2", "physnet2", "eth2"),
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

    def test_multiple_changes(self):
        old_map = [
            BridgeMapping("br-old", "physnet1", "eth0"),
            BridgeMapping("br-physnet2", "physnet2", "eth1"),
        ]
        new_map = [
            BridgeMapping("br-physnet2", "physnet2", "eth2"),
            BridgeMapping("br-new", "physnet1", "eth4"),
            BridgeMapping("br-physnet3", "physnet3", "eth1"),
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
            BridgeMapping("br-ex", "physnet1", "eth0"),
            BridgeMapping("br-physnet2", "physnet2", "eth1"),
        ]
        new_map = [
            BridgeMapping("br-ex", "physnet1", "eth0"),
            BridgeMapping("br-physnet3", "physnet3", "eth1"),
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
    def test_empty_all_parameters(self):
        result = resolve_bridge_mappings("", "", "", "")
        assert result == []

    def test_basic_bridge_physnet_mapping_only(self):
        result = resolve_bridge_mappings("", "", "", "br-ex:physnet1 br-data:physnet2")
        assert result == [
            BridgeMapping("br-ex", "physnet1", None),
            BridgeMapping("br-data", "physnet2", None),
        ]

    def test_bridge_and_interface_mapping(self):
        result = resolve_bridge_mappings(
            "",
            "",
            "",
            "br-ex:physnet1:eth0 br-data:physnet2:eth1",
        )
        assert result == [
            BridgeMapping("br-ex", "physnet1", "eth0"),
            BridgeMapping("br-data", "physnet2", "eth1"),
        ]

    def test_partial_interface_mapping(self):
        result = resolve_bridge_mappings(
            "",
            "",
            "",
            "br-ex:physnet1:eth0 br-data:physnet2",
        )
        assert BridgeMapping("br-ex", "physnet1", "eth0") in result
        assert BridgeMapping("br-data", "physnet2", None) in result

    def test_legacy_external_bridge_params(self):
        result = resolve_bridge_mappings("br-ex", "physnet-ext", "eth0", "")
        assert result == [BridgeMapping("br-ex", "physnet-ext", "eth0")]

    def test_legacy_external_bridge_with_empty_nic(self):
        result = resolve_bridge_mappings("br-ex", "physnet-ext", "", "")
        assert result == [BridgeMapping("br-ex", "physnet-ext", None)]

    def test_legacy_params_override_by_new_params(self):
        result = resolve_bridge_mappings(
            "br-old",
            "physnet-old",
            "eth9",
            "br-new:physnet1:eth0",
        )
        assert result == [BridgeMapping("br-new", "physnet1", "eth0")]

    def test_whitespace_handling(self):
        result = resolve_bridge_mappings(
            "",
            "",
            "",
            "  br-ex:physnet1   br-data:physnet2  ",
        )
        assert result == [
            BridgeMapping("br-ex", "physnet1", None),
            BridgeMapping("br-data", "physnet2", None),
        ]

    def test_single_bridge_mapping(self):
        result = resolve_bridge_mappings("", "", "", "br-ex:physnet1:eth0")
        assert result == [BridgeMapping("br-ex", "physnet1", "eth0")]

    def test_multiple_bridges_single_interface(self):
        result = resolve_bridge_mappings(
            "",
            "",
            "",
            "br-ex:physnet1 br-data:physnet2:eth1 br-tenant:physnet3",
        )
        assert len(result) == 3
        assert BridgeMapping("br-ex", "physnet1", None) in result
        assert BridgeMapping("br-data", "physnet2", "eth1") in result
        assert BridgeMapping("br-tenant", "physnet3", None) in result

    def test_complex_mapping_scenario(self):
        result = resolve_bridge_mappings(
            "",
            "",
            "",
            "br-ex:physnet-public:bond0 br-data:physnet-data:eth1 br-tenant:physnet-tenant:vlan100",
        )
        assert len(result) == 3
        assert BridgeMapping("br-ex", "physnet-public", "bond0") in result
        assert BridgeMapping("br-data", "physnet-data", "eth1") in result
        assert BridgeMapping("br-tenant", "physnet-tenant", "vlan100") in result

    def test_invalid_mapping_format(self):
        with pytest.raises(ValueError, match="Invalid mapping format"):
            resolve_bridge_mappings(
                "",
                "",
                "",
                "br-ex:physnet1 invalidmapping br-data:physnet2",
            )

    def test_multiple_invalid_mappings(self):
        with pytest.raises(ValueError, match="Invalid mapping format"):
            resolve_bridge_mappings(
                "",
                "",
                "",
                "br-ex:physnet1 bad1 bad2 br-data:physnet2",
            )

    def test_empty_physnet_name_legacy(self):
        result = resolve_bridge_mappings("br-ex", "", "eth0", "")
        assert result == []

    def test_empty_bridge_name_legacy(self):
        result = resolve_bridge_mappings("", "physnet-ext", "eth0", "")
        assert result == []

    def test_bridge_name_with_special_chars(self):
        result = resolve_bridge_mappings(
            "",
            "",
            "",
            "br-ex-123:physnet-1 br_data_456:physnet_2:bond0",
        )
        assert BridgeMapping("br-ex-123", "physnet-1", None) in result
        assert BridgeMapping("br_data_456", "physnet_2", "bond0") in result

    def test_interface_name_with_vlan_tags(self):
        result = resolve_bridge_mappings("", "", "", "br-ex:physnet1:eth0.100")
        assert result == [BridgeMapping("br-ex", "physnet1", "eth0.100")]

    def test_interface_name_with_bond(self):
        result = resolve_bridge_mappings("", "", "", "br-ex:physnet1:bond0")
        assert result == [BridgeMapping("br-ex", "physnet1", "bond0")]

    def test_order_preservation(self):
        result = resolve_bridge_mappings(
            "",
            "",
            "",
            "br-ex:physnet1 br-data:physnet2 br-tenant:physnet3",
        )
        assert [m.bridge for m in result] == ["br-ex", "br-data", "br-tenant"]

    def test_duplicate_physnet_names(self):
        with pytest.raises(ValueError, match="Duplicate physnet in mapping: physnet1"):
            resolve_bridge_mappings(
                "",
                "",
                "",
                "br-ex:physnet1 br-data:physnet1",
            )

    def test_duplicate_bridge_names(self):
        with pytest.raises(ValueError, match="Duplicate bridge in mapping: br-ex"):
            resolve_bridge_mappings(
                "",
                "",
                "",
                "br-ex:physnet1 br-ex:physnet2",
            )

    def test_case_sensitivity(self):
        result = resolve_bridge_mappings(
            "",
            "",
            "",
            "BR-EX:PhysNet1:ETH0 br-ex:physnet1:eth0",
        )
        assert BridgeMapping("BR-EX", "PhysNet1", "ETH0") in result
        assert BridgeMapping("br-ex", "physnet1", "eth0") in result

    def test_physnet_bridge_pair_method(self):
        mapping = BridgeMapping("br-ex", "physnet1", "eth0")
        assert mapping.physnet_bridge_pair() == "physnet1:br-ex"

    def test_bridge_mapping_immutability(self):
        mapping = BridgeMapping("br-ex", "physnet1", "eth0")
        try:
            mapping.physnet = "physnet2"  # type: ignore[attr-defined]
            assert False, "Should not allow modification of frozen dataclass"
        except (AttributeError, TypeError):
            pass

    def test_none_interface_representation(self):
        result = resolve_bridge_mappings("", "", "", "br-ex:physnet1")
        assert result == [BridgeMapping("br-ex", "physnet1", None)]


class TestDetectCurrentMappings:
    def test_detect_current_mappings_success(self):
        def fake_vsctl(*args, retry=True, skip_transaction=False):
            command = tuple(args)
            if command == ("list-br",):
                return "br-data\nbr-ex\n"
            if command == ("get", "open", ".", "external_ids:ovn-bridge-mappings"):
                return '"physnet2:br-data,physnet1:br-ex"\n'
            if command == ("list-ifaces", "br-data"):
                return "br-data\nbond0\n"
            if command == ("list-ifaces", "br-ex"):
                return "br-ex\neth0\n"
            if command == (
                "--bare",
                "--columns=name",
                "find",
                "Interface",
                "type!=patch",
                "type!=internal",
            ):
                return "bond0\neth0\n"
            raise AssertionError(f"Unexpected ovs-vsctl call: {command}")

        ovs_cli = OVSCli()
        with patch.object(ovs_cli, "vsctl", side_effect=fake_vsctl):
            result = detect_current_mappings(ovs_cli)

        assert set(result) == {
            BridgeMapping("br-ex", "physnet1", "eth0"),
            BridgeMapping("br-data", "physnet2", "bond0"),
        }

    def test_detect_current_mappings_ovs_error(self):
        ovs_cli = OVSCli()
        with patch.object(ovs_cli, "vsctl", side_effect=OVSCommandError("boom")) as mock_vsctl:
            result = detect_current_mappings(ovs_cli)

        assert result == []
        mock_vsctl.assert_called_once_with("list-br", skip_transaction=True)


def _is_byte_hex(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9A-Fa-f]{2}", s))


class TestGenerateStableLaaMac:
    def test_generate_stable_laa_mac_deterministic_and_format(self):
        prefix = DEFAULT_LAA_MAC_PREFIX
        physnet = "physnet1"
        machine_id = "machine-uuid-1234"

        mac1 = generate_stable_laa_mac(prefix, physnet, machine_id)
        mac2 = generate_stable_laa_mac(prefix, physnet, machine_id)

        assert mac1 == mac2
        assert mac1.startswith(f"{prefix}:")
        parts = mac1.split(":")
        assert len(parts) == 6
        for part in parts:
            assert _is_byte_hex(part)
            assert 0 <= int(part, 16) <= 0xFF

    def test_generate_stable_laa_mac_matches_hash_bytes(self):
        prefix = DEFAULT_LAA_MAC_PREFIX
        physnet = "physnet-xyz"
        machine_id = "node-42"
        physnet_hash = hashlib.sha256(physnet.encode("utf-8")).digest()
        machine_hash = hashlib.sha256(machine_id.encode("utf-8")).digest()

        expected = (
            f"{prefix}:"
            f"{physnet_hash[0]:02x}:"
            f"{machine_hash[0]:02x}:{machine_hash[1]:02x}:{machine_hash[2]:02x}"
        )

        assert generate_stable_laa_mac(prefix, physnet, machine_id) == expected

    def test_generate_stable_laa_mac_invalid_prefix_length(self):
        with pytest.raises(ValueError):
            generate_stable_laa_mac("0A", "physnet", "machine")

    def test_generate_stable_laa_mac_invalid_prefix_hex(self):
        with pytest.raises(ValueError):
            generate_stable_laa_mac("GG:C5", "physnet", "machine")

    def test_generate_stable_laa_mac_requires_laa_bit_set(self):
        # first octet 00 does not have the LAA bit (0x02) set
        with pytest.raises(ValueError):
            generate_stable_laa_mac("00:C5", "physnet", "machine")


class TestUpdateMappingsFromRename:
    def test_no_renames(self):
        mappings = [BridgeMapping("br-ex", "physnet1", "eth0")]
        assert update_mappings_from_rename(mappings, []) == mappings

    def test_rename_existing_bridge(self):
        mappings = [BridgeMapping("br-new", "physnet1", "eth0")]
        renames = [("br-old", "br-new")]
        expected = [BridgeMapping("br-old", "physnet1", "eth0")]
        assert update_mappings_from_rename(mappings, renames) == expected

    def test_rename_non_existing_bridge(self):
        mappings = [BridgeMapping("br-other", "physnet1", "eth0")]
        renames = [("br-old", "br-new")]
        assert update_mappings_from_rename(mappings, renames) == mappings

    def test_multiple_renames(self):
        mappings = [
            BridgeMapping("br-new1", "physnet1", "eth0"),
            BridgeMapping("br-new2", "physnet2", "eth1"),
            BridgeMapping("br-static", "physnet3", "eth2"),
        ]
        renames = [("br-old1", "br-new1"), ("br-old2", "br-new2")]
        expected = [
            BridgeMapping("br-old1", "physnet1", "eth0"),
            BridgeMapping("br-old2", "physnet2", "eth1"),
            BridgeMapping("br-static", "physnet3", "eth2"),
        ]
        assert update_mappings_from_rename(mappings, renames) == expected

    def test_rename_with_missing_mapping(self):
        # Rename exists but no mapping uses the new name
        mappings = [BridgeMapping("br-static", "physnet3", "eth2")]
        renames = [("br-old", "br-new")]
        assert update_mappings_from_rename(mappings, renames) == mappings


class TestBridgeRenameSafety:
    def test_is_bridge_rename_safe_uses_fallback_sb_timeout(self):
        ovs = OVSCli()

        def fake_vsctl(*args, **kwargs):
            if args == ("get", "open", ".", "external_ids:ovn-remote"):
                return '"tcp:127.0.0.1:6642"\n'
            if args == ("get", "open", ".", "external_ids:system-id"):
                return '"node.example.com"\n'
            raise AssertionError(f"Unexpected ovs-vsctl call: {args}")

        with (
            patch.object(ovs, "vsctl", side_effect=fake_vsctl),
            patch("openstack_hypervisor.bridge_datapath.OVNSBCli") as mock_ovn_sb_cls,
            patch(
                "openstack_hypervisor.bridge_datapath._find_local_chassis_uuid",
                return_value=None,
            ),
        ):
            assert is_bridge_rename_safe(ovs) is True

        mock_ovn_sb_cls.assert_called_once_with(
            "tcp:127.0.0.1:6642",
            timeout=SB_RENAME_SAFE_QUERY_TIMEOUT_S,
        )

    def test_is_bridge_rename_safe_preserves_explicit_sb_timeout(self):
        ovs = OVSCli(timeout=7)

        def fake_vsctl(*args, **kwargs):
            if args == ("get", "open", ".", "external_ids:ovn-remote"):
                return '"tcp:127.0.0.1:6642"\n'
            if args == ("get", "open", ".", "external_ids:system-id"):
                return '"node.example.com"\n'
            raise AssertionError(f"Unexpected ovs-vsctl call: {args}")

        with (
            patch.object(ovs, "vsctl", side_effect=fake_vsctl),
            patch("openstack_hypervisor.bridge_datapath.OVNSBCli") as mock_ovn_sb_cls,
            patch(
                "openstack_hypervisor.bridge_datapath._find_local_chassis_uuid",
                return_value=None,
            ),
        ):
            assert is_bridge_rename_safe(ovs) is True

        mock_ovn_sb_cls.assert_called_once_with("tcp:127.0.0.1:6642", timeout=7)

    def test_is_bridge_rename_safe_when_ovn_remote_missing(self):
        ovs = OVSCli()
        with patch.object(ovs, "vsctl", return_value="[]\n") as mock_vsctl:
            assert is_bridge_rename_safe(ovs) is True
        mock_vsctl.assert_called_once_with(
            "get",
            "open",
            ".",
            "external_ids:ovn-remote",
            skip_transaction=True,
        )

    def test_is_bridge_rename_safe_fails_closed_when_ovn_remote_query_fails(self):
        ovs = OVSCli()
        with patch.object(ovs, "vsctl", side_effect=OVSCommandError("ovs failed")):
            assert is_bridge_rename_safe(ovs) is False

    def test_is_bridge_rename_safe_when_system_id_missing(self):
        ovs = OVSCli()

        def fake_vsctl(*args, **kwargs):
            if args == ("get", "open", ".", "external_ids:ovn-remote"):
                return '"tcp:127.0.0.1:6642"\n'
            if args == ("get", "open", ".", "external_ids:system-id"):
                return "[]\n"
            raise AssertionError(f"Unexpected ovs-vsctl call: {args}")

        with patch.object(ovs, "vsctl", side_effect=fake_vsctl):
            assert is_bridge_rename_safe(ovs) is True

    def test_is_bridge_rename_safe_fails_closed_when_system_id_query_fails(self):
        ovs = OVSCli()

        def fake_vsctl(*args, **kwargs):
            if args == ("get", "open", ".", "external_ids:ovn-remote"):
                return '"tcp:127.0.0.1:6642"\n'
            if args == ("get", "open", ".", "external_ids:system-id"):
                raise OVSCommandError("ovs failed")
            raise AssertionError(f"Unexpected ovs-vsctl call: {args}")

        with patch.object(ovs, "vsctl", side_effect=fake_vsctl):
            assert is_bridge_rename_safe(ovs) is False

    def test_is_bridge_rename_safe_when_chassis_missing(self):
        ovs = OVSCli()
        chassis_output = json.dumps({"headings": ["_uuid"], "data": []})

        def fake_vsctl(*args, **kwargs):
            if args == ("get", "open", ".", "external_ids:ovn-remote"):
                return '"tcp:127.0.0.1:6642"\n'
            if args == ("get", "open", ".", "external_ids:system-id"):
                return '"node.example.com"\n'
            raise AssertionError(f"Unexpected ovs-vsctl call: {args}")

        with (
            patch.object(ovs, "vsctl", side_effect=fake_vsctl),
            patch.object(OVNSBCli, "sbctl", return_value=chassis_output) as mock_sbctl,
        ):
            assert is_bridge_rename_safe(ovs) is True

        mock_sbctl.assert_called_once_with(
            "--format=json",
            "--columns=_uuid",
            "find",
            "Chassis",
            "name=node.example.com",
        )

    def test_is_bridge_rename_safe_when_local_chassis_has_no_bindings(self):
        ovs = OVSCli()
        chassis_uuid = "fd8d4990-a66f-45cb-9881-cae642ef2796"
        chassis_output = json.dumps({"headings": ["_uuid"], "data": [[["uuid", chassis_uuid]]]})
        bindings_output = json.dumps({"headings": ["_uuid"], "data": []})

        def fake_vsctl(*args, **kwargs):
            if args == ("get", "open", ".", "external_ids:ovn-remote"):
                return '"tcp:127.0.0.1:6642"\n'
            if args == ("get", "open", ".", "external_ids:system-id"):
                return '"node.example.com"\n'
            raise AssertionError(f"Unexpected ovs-vsctl call: {args}")

        with (
            patch.object(ovs, "vsctl", side_effect=fake_vsctl),
            patch.object(
                OVNSBCli,
                "sbctl",
                side_effect=[chassis_output, bindings_output],
            ) as mock_sbctl,
        ):
            assert is_bridge_rename_safe(ovs) is True

        assert mock_sbctl.call_count == 2
        assert mock_sbctl.call_args_list[1].args == (
            "--format=json",
            "--columns=_uuid",
            "find",
            "Port_Binding",
            f"chassis={chassis_uuid}",
        )

    def test_is_bridge_rename_safe_when_local_chassis_has_bindings(self):
        ovs = OVSCli()
        chassis_uuid = "fd8d4990-a66f-45cb-9881-cae642ef2796"
        chassis_output = json.dumps({"headings": ["_uuid"], "data": [[["uuid", chassis_uuid]]]})
        bindings_output = json.dumps({"headings": ["_uuid"], "data": [[["uuid", "binding-uuid"]]]})

        def fake_vsctl(*args, **kwargs):
            if args == ("get", "open", ".", "external_ids:ovn-remote"):
                return '"tcp:127.0.0.1:6642"\n'
            if args == ("get", "open", ".", "external_ids:system-id"):
                return '"node.example.com"\n'
            raise AssertionError(f"Unexpected ovs-vsctl call: {args}")

        with (
            patch.object(ovs, "vsctl", side_effect=fake_vsctl),
            patch.object(
                OVNSBCli,
                "sbctl",
                side_effect=[chassis_output, bindings_output],
            ),
        ):
            assert is_bridge_rename_safe(ovs) is False

    def test_is_bridge_rename_safe_fails_closed_when_sb_query_fails(self):
        ovs = OVSCli()

        def fake_vsctl(*args, **kwargs):
            if args == ("get", "open", ".", "external_ids:ovn-remote"):
                return '"tcp:127.0.0.1:6642"\n'
            if args == ("get", "open", ".", "external_ids:system-id"):
                return '"node.example.com"\n'
            raise AssertionError(f"Unexpected ovs-vsctl call: {args}")

        with (
            patch.object(ovs, "vsctl", side_effect=fake_vsctl),
            patch.object(
                OVNSBCli,
                "sbctl",
                side_effect=OVNCommandError("sb failed"),
            ),
            patch("openstack_hypervisor.bridge_datapath.time.sleep"),
        ):
            assert is_bridge_rename_safe(ovs) is False

    def test_is_bridge_rename_safe_retries_strict_sb_queries(self):
        ovs = OVSCli()

        def fake_vsctl(*args, **kwargs):
            if args == ("get", "open", ".", "external_ids:ovn-remote"):
                return '"tcp:127.0.0.1:6642"\n'
            if args == ("get", "open", ".", "external_ids:system-id"):
                return '"node.example.com"\n'
            raise AssertionError(f"Unexpected ovs-vsctl call: {args}")

        with (
            patch.object(ovs, "vsctl", side_effect=fake_vsctl),
            patch.object(
                OVNSBCli,
                "sbctl",
                side_effect=OVNCommandError("sb failed"),
            ) as mock_sbctl,
            patch("openstack_hypervisor.bridge_datapath.time.sleep") as mock_sleep,
        ):
            assert is_bridge_rename_safe(ovs) is False

        assert mock_sbctl.call_count == 3
        assert mock_sleep.call_count == 2

    def test_is_bridge_rename_safe_retries_on_sb_timeout(self):
        ovs = OVSCli()

        def fake_vsctl(*args, **kwargs):
            if args == ("get", "open", ".", "external_ids:ovn-remote"):
                return '"tcp:127.0.0.1:6642"\n'
            if args == ("get", "open", ".", "external_ids:system-id"):
                return '"node.example.com"\n'
            raise AssertionError(f"Unexpected ovs-vsctl call: {args}")

        with (
            patch.object(ovs, "vsctl", side_effect=fake_vsctl),
            patch.object(
                OVNSBCli,
                "sbctl",
                side_effect=OVNTimeoutError("sb timeout"),
            ) as mock_sbctl,
            patch("openstack_hypervisor.bridge_datapath.time.sleep") as mock_sleep,
        ):
            assert is_bridge_rename_safe(ovs) is False

        assert mock_sbctl.call_count == 3
        assert mock_sleep.call_count == 2

    def test_is_bridge_rename_safe_fails_closed_when_sb_times_out(self):
        ovs = OVSCli()

        def fake_vsctl(*args, **kwargs):
            if args == ("get", "open", ".", "external_ids:ovn-remote"):
                return '"tcp:127.0.0.1:6642"\n'
            if args == ("get", "open", ".", "external_ids:system-id"):
                return '"node.example.com"\n'
            raise AssertionError(f"Unexpected ovs-vsctl call: {args}")

        with (
            patch.object(ovs, "vsctl", side_effect=fake_vsctl),
            patch.object(
                OVNSBCli,
                "sbctl",
                side_effect=OVNTimeoutError("sb timeout"),
            ),
            patch("openstack_hypervisor.bridge_datapath.time.sleep"),
        ):
            assert is_bridge_rename_safe(ovs) is False

    def test_is_bridge_rename_safe_allows_stale_sb_reads(self):
        ovs = OVSCli()
        chassis_output = json.dumps({"headings": ["_uuid"], "data": []})

        def fake_vsctl(*args, **kwargs):
            if args == ("get", "open", ".", "external_ids:ovn-remote"):
                return '"tcp:127.0.0.1:6642"\n'
            if args == ("get", "open", ".", "external_ids:system-id"):
                return '"node.example.com"\n'
            raise AssertionError(f"Unexpected ovs-vsctl call: {args}")

        with (
            patch.object(ovs, "vsctl", side_effect=fake_vsctl),
            patch.object(OVNSBCli, "sbctl", return_value=chassis_output) as mock_sbctl,
        ):
            assert is_bridge_rename_safe(ovs, allow_stale_sb_read=True) is True

        mock_sbctl.assert_called_once_with(
            "--format=json",
            "--columns=_uuid",
            "find",
            "Chassis",
            "name=node.example.com",
            allow_stale_reads=True,
        )


class TestOVNSBCli:
    def test_rename_safety_query_raises_for_invalid_retry_count(self, monkeypatch):
        ovn_sb = OVNSBCli("tcp:127.0.0.1:6642")
        monkeypatch.setattr(
            "openstack_hypervisor.bridge_datapath.SB_RENAME_SAFE_QUERY_RETRIES",
            0,
        )

        with pytest.raises(ValueError, match="SB_RENAME_SAFE_QUERY_RETRIES must be >= 1"):
            ovn_sb.rename_safety_query("show")

    def test_rename_safety_query_returns_when_last_retry_succeeds(self):
        ovn_sb = OVNSBCli("tcp:127.0.0.1:6642")

        with (
            patch.object(
                ovn_sb,
                "sbctl",
                side_effect=[OVNCommandError("first"), OVNCommandError("second"), "ok"],
            ) as mock_sbctl,
            patch("openstack_hypervisor.bridge_datapath.time.sleep") as mock_sleep,
        ):
            assert ovn_sb.rename_safety_query("show") == "ok"

        assert mock_sbctl.call_count == 3
        assert mock_sleep.call_count == 2


class TestOVSCli:

    def test_list_bridge_interfaces_filters_types(self):
        ovs = OVSCli()
        with patch.object(ovs, "vsctl") as mock_vsctl:

            def fake_vsctl(*args, retry=True, skip_transaction=False):
                if args[0] == "list-ifaces":
                    return "eth0\npatch-port\ninternal-port\n"
                if args[0] == "--bare" and "find" in args:
                    return "eth0\n"
                return ""

            mock_vsctl.side_effect = fake_vsctl

            ifaces = ovs.list_bridge_interfaces("br-ex")
            assert ifaces == ["eth0"]

            mock_vsctl.assert_any_call("list-ifaces", "br-ex", skip_transaction=True)
            mock_vsctl.assert_any_call(
                "--bare",
                "--columns=name",
                "find",
                "Interface",
                "type!=patch",
                "type!=internal",
                skip_transaction=True,
            )

    def test_list_table(self):
        ovs = OVSCli()
        mock_data = """
{"data":[[["map",[["dpdk-init","try"],["dpdk-socket-mem","4096"]]]]],"headings":["other_config"]}
"""
        with patch.object(ovs, "vsctl", return_value=mock_data):
            out = ovs.list_table("mock-table", "mock-record", ["mock-column"])

            exp_out = {
                "other_config": {
                    "dpdk-init": "try",
                    "dpdk-socket-mem": "4096",
                }
            }
            assert exp_out == out

    def test_set(self):
        ovs = OVSCli()
        with patch.object(ovs, "vsctl") as mock_vsctl:
            ovs.set(
                "mock-table",
                "mock-record",
                "mock-column",
                {"key1": "val1", "key2": "val2"},
            )

            mock_vsctl.assert_called_once_with(
                "set",
                "mock-table",
                "mock-record",
                "mock-column:key1=val1",
                "mock-column:key2=val2",
            )

    def test_set_check(self):
        ovs = OVSCli()
        mock_current_settings = {
            "dpdk-init": "try",
            "dpdk-socket-mem": "4096",
        }
        mock_updates = {
            "hw-offload": "true",
        }
        mock_applied_settings = dict(mock_current_settings)
        mock_applied_settings.update(mock_updates)

        with (
            patch.object(ovs, "list_table") as mock_list_table,
            patch.object(ovs, "set"),
        ):
            mock_list_table.side_effect = [
                {"other_config": mock_current_settings},
                {"other_config": mock_applied_settings},
            ]

            config_changed = ovs.set_check(
                "mock-table", "mock-record", "other_config", mock_updates
            )
            assert config_changed

            config_changed = ovs.set_check(
                "mock-table", "mock-record", "other_config", mock_updates
            )
            assert not config_changed

    def test_add_bridge(self):
        ovs = OVSCli()
        with patch.object(ovs, "vsctl") as mock_vsctl:
            ovs.add_bridge("bridge-name", "datapath-name", "fake-arg")

            mock_vsctl.assert_called_once_with(
                "--may-exist",
                "add-br",
                "bridge-name",
                "--",
                "set",
                "bridge",
                "bridge-name",
                "datapath_type=datapath-name",
                "fake-arg",
            )

    def test_del_port(self):
        ovs = OVSCli()
        with patch.object(ovs, "vsctl") as mock_vsctl:
            ovs.del_port("bridge-name", "port-name")

            mock_vsctl.assert_called_once_with(
                "--if-exists", "del-port", "bridge-name", "port-name"
            )

    def test_add_port(self):
        ovs = OVSCli()
        with patch.object(ovs, "vsctl") as mock_vsctl:
            ovs.add_port(
                "bridge-name",
                "port-name",
                port_type="dpdk",
                options={"dpdk-devargs": "pci-address"},
                mtu=9000,
            )

            mock_vsctl.assert_called_once_with(
                "--may-exist",
                "add-port",
                "bridge-name",
                "port-name",
                "--",
                "set",
                "Interface",
                "port-name",
                "type=dpdk",
                "--",
                "set",
                "Interface",
                "port-name",
                "mtu-request=9000",
                "--",
                "set",
                "Interface",
                "port-name",
                "options:dpdk-devargs=pci-address",
            )

    def test_appctl_success(self):
        """Test appctl executes successfully and returns output."""
        ovs = OVSCli("unix:/some/db.sock", switchd_ctl_socket="unix:/some/ctl.sock")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = "dpctl/show output"
            mock_run.return_value.returncode = 0

            result = ovs.appctl("dpctl/show")

            assert result == "dpctl/show output"
            mock_run.assert_called_once()
            call_args = mock_run.call_args
            assert call_args[0][0] == [
                "ovs-appctl",
                "--target",
                "unix:/some/ctl.sock",
                "dpctl/show",
            ]

    def test_appctl_no_socket_raises_error(self):
        """Test appctl raises OVSCommandError when switchd_ctl_socket is not set."""
        ovs = OVSCli("unix:/some/db.sock")
        with pytest.raises(OVSCommandError, match="switchd_ctl_socket is not configured"):
            ovs.appctl("dpctl/show")

    def test_appctl_binary_not_found(self):
        """Test appctl raises OVSCommandError when binary not found."""
        ovs = OVSCli("unix:/some/db.sock", switchd_ctl_socket="unix:/some/ctl.sock")
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()

            with pytest.raises(OVSCommandError, match="ovs-appctl binary not found"):
                ovs.appctl("dpctl/show")

    def test_appctl_command_error(self):
        """Test appctl raises OVSCommandError on command failure."""
        import subprocess

        ovs = OVSCli("unix:/some/db.sock", switchd_ctl_socket="unix:/some/ctl.sock")
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "cmd", stderr="error message")

            with pytest.raises(OVSCommandError, match="error message"):
                ovs.appctl("dpctl/show")

    def test_get_dpdk_initialized_true(self):
        """Test get_dpdk_initialized returns True when DPDK is initialized."""
        ovs = OVSCli()
        with patch.object(ovs, "vsctl") as mock_vsctl:
            mock_vsctl.return_value = '"true"\n'

            result = ovs.get_dpdk_initialized()

            assert result is True
            mock_vsctl.assert_called_once_with(
                "get", "Open_vSwitch", ".", "dpdk_initialized", skip_transaction=True
            )

    def test_get_dpdk_initialized_false(self):
        """Test get_dpdk_initialized returns False when DPDK is not initialized."""
        ovs = OVSCli()
        with patch.object(ovs, "vsctl") as mock_vsctl:
            mock_vsctl.return_value = '"false"\n'

            result = ovs.get_dpdk_initialized()

            assert result is False

    def test_get_dpdk_initialized_on_error(self):
        """Test get_dpdk_initialized returns False on command error."""
        ovs = OVSCli()
        with patch.object(ovs, "vsctl") as mock_vsctl:
            mock_vsctl.side_effect = OVSCommandError("error")

            result = ovs.get_dpdk_initialized()

            assert result is False
