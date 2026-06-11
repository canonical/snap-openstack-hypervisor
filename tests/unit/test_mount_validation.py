# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from openstack_hypervisor.mount_validation import (
    is_mounted,
    is_usable,
    path_declared_in_fstab,
    validate_instances_mount,
)

_INSTANCES_PATH = Path("/var/snap/openstack-hypervisor/common/lib/nova/instances")


@pytest.fixture
def fstab(tmp_path):
    return tmp_path / "fstab"


@pytest.fixture
def instances_dir(tmp_path):
    d = tmp_path / "instances"
    d.mkdir()
    return d


class TestPathDeclaredInFstab:
    """Tests for path_declared_in_fstab()."""

    def test_returns_false_when_no_matching_entry(self, fstab):
        """Returns False when no fstab entry targets the instances path."""
        fstab.write_text("/dev/sda1 / ext4 defaults 0 1\n" "/dev/sda2 /boot ext4 defaults 0 2\n")
        assert path_declared_in_fstab(_INSTANCES_PATH, fstab) is False

    def test_returns_true_when_matching_entry_exists(self, fstab):
        """Returns True when fstab has a line whose mount target matches."""
        fstab.write_text(
            "/dev/sda1 / ext4 defaults 0 1\n" f"/dev/sdb1 {_INSTANCES_PATH} ext4 defaults 0 0\n"
        )
        assert path_declared_in_fstab(_INSTANCES_PATH, fstab) is True

    def test_returns_false_when_fstab_unreadable(self, tmp_path):
        """Returns False when fstab cannot be read."""
        missing = tmp_path / "not_fstab"
        assert path_declared_in_fstab(_INSTANCES_PATH, missing) is False

    def test_ignores_comments_and_blank_lines(self, fstab):
        fstab.write_text("\n" "# comment\n" f"/dev/sdb {_INSTANCES_PATH} ext4 defaults 0 0\n")
        assert path_declared_in_fstab(_INSTANCES_PATH, fstab) is True


class TestIsMounted:
    """Tests for is_mounted()."""

    def test_returns_true_when_findmnt_succeeds(self):
        """Returns True when findmnt exits with returncode 0."""
        mock_result = MagicMock(returncode=0)
        with patch(
            "openstack_hypervisor.mount_validation.subprocess.run", return_value=mock_result
        ) as mock_run:
            assert is_mounted(_INSTANCES_PATH) is True
        mock_run.assert_called_once_with(
            ["findmnt", "--mountpoint", str(_INSTANCES_PATH)],
            capture_output=True,
            check=False,
        )

    def test_returns_false_when_findmnt_fails(self):
        """Returns False when findmnt exits with a non-zero returncode."""
        mock_result = MagicMock(returncode=1)
        with patch(
            "openstack_hypervisor.mount_validation.subprocess.run", return_value=mock_result
        ):
            assert is_mounted(_INSTANCES_PATH) is False


class TestIsUsable:
    """Tests for is_usable()."""

    def test_returns_true_for_writable_directory(self, instances_dir):
        """Returns True when the path is a directory and a file can be created."""
        assert is_usable(instances_dir) is True

    def test_returns_false_when_path_does_not_exist(self, tmp_path):
        """Returns False when the path does not exist."""
        assert is_usable(tmp_path / "nonexistent") is False

    def test_returns_false_when_path_is_a_file(self, tmp_path):
        """Returns False when the path is a regular file, not a directory."""
        f = tmp_path / "notadir"
        f.write_text("content")
        assert is_usable(f) is False

    def test_returns_false_when_write_fails(self, instances_dir):
        """Returns False when a temporary file cannot be created in the directory."""
        with patch(
            "openstack_hypervisor.mount_validation.tempfile.TemporaryFile",
            side_effect=OSError("read-only"),
        ):
            assert is_usable(instances_dir) is False


class TestValidateInstancesMount:
    """Tests for validate_instances_mount()."""

    def test_returns_true_when_no_fstab_entry(self, fstab):
        """Returns True without checking mount when no fstab entry exists."""
        fstab.write_text("/dev/sda1 / ext4 defaults 0 1\n")
        with patch("openstack_hypervisor.mount_validation.is_mounted") as mock_mounted:
            result = validate_instances_mount(_INSTANCES_PATH, fstab)
        assert result is True
        mock_mounted.assert_not_called()

    def test_returns_true_when_mounted_and_usable(self, fstab):
        """Returns True when fstab entry exists, path is mounted, and writable."""
        fstab.write_text(f"/dev/sdb1 {_INSTANCES_PATH} ext4 defaults 0 0\n")
        with patch("openstack_hypervisor.mount_validation.is_mounted", return_value=True), patch(
            "openstack_hypervisor.mount_validation.is_usable", return_value=True
        ):
            assert validate_instances_mount(_INSTANCES_PATH, fstab) is True

    def test_returns_false_when_fstab_entry_but_not_mounted(self, fstab):
        """Returns False when fstab entry exists but path is not mounted."""
        fstab.write_text(f"/dev/sdb1 {_INSTANCES_PATH} ext4 defaults 0 0\n")
        with patch("openstack_hypervisor.mount_validation.is_mounted", return_value=False), patch(
            "openstack_hypervisor.mount_validation.LOG"
        ) as mock_log:
            assert validate_instances_mount(_INSTANCES_PATH, fstab) is False
        assert "not mounted" in mock_log.error.call_args.args[0]

    def test_returns_false_when_mounted_but_not_usable(self, fstab):
        """Returns False when path is mounted but not writable."""
        fstab.write_text(f"/dev/sdb1 {_INSTANCES_PATH} ext4 defaults 0 0\n")
        with patch("openstack_hypervisor.mount_validation.is_mounted", return_value=True), patch(
            "openstack_hypervisor.mount_validation.is_usable", return_value=False
        ), patch("openstack_hypervisor.mount_validation.LOG") as mock_log:
            assert validate_instances_mount(_INSTANCES_PATH, fstab) is False
        assert "not a writable directory" in mock_log.error.call_args.args[0]
