# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import logging
import subprocess
import tempfile
from pathlib import Path

LOG = logging.getLogger(__name__)


def path_declared_in_fstab(
    path: Path,
    fstab_path: Path = Path("/etc/fstab"),
) -> bool:
    """Return True if /etc/fstab has an entry targeting the given path."""
    try:
        text = fstab_path.read_text()
    except UnicodeError:
        LOG.exception("Could not decode %s, aborting mount validation.", fstab_path)
        raise
    except OSError as exc:
        LOG.warning("Could not read %s (%s), skipping mount validation.", fstab_path, exc)
        return False

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) >= 2 and Path(fields[1]) == path:
            return True
    return False


def is_mounted(path: Path) -> bool:
    """Return True if path is an active mount point."""
    try:
        result = subprocess.run(
            ["findmnt", "--mountpoint", str(path)],
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        LOG.warning("Unable to execute findmnt (%s).", exc)
        return False
    return result.returncode == 0


def is_usable(path: Path) -> bool:
    """Return True if path is a writable directory."""
    if not path.is_dir():
        return False
    try:
        with tempfile.TemporaryFile(dir=path):
            return True
    except OSError as exc:
        LOG.warning("Couldn't create temporary file in %s, path is not writable (%s).", path, exc)
        return False


def validate_instances_mount(
    instances_path: Path,
    fstab_path: Path = Path("/etc/fstab"),
) -> bool:
    """Validate externally managed storage mount for Nova's instance path."""
    if not path_declared_in_fstab(instances_path, fstab_path):
        LOG.debug("No fstab entry for %s, skipping mount validation.", instances_path)
        return True

    LOG.info("fstab entry found for %s, validating mount.", instances_path)

    if not is_mounted(instances_path):
        LOG.error(
            "Instances path %s is declared in /etc/fstab but is not mounted. "
            "nova-compute will not start until the path is mounted.",
            instances_path,
        )
        return False

    if not is_usable(instances_path):
        LOG.error(
            "Instances path %s is mounted but not a writable directory."
            " Check mount status, filesystem health, and permissions. "
            "nova-compute will not start.",
            instances_path,
        )
        return False
    LOG.info("Instances path %s is mounted and writable.", instances_path)
    return True
