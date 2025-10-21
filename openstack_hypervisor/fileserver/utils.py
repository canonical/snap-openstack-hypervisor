"""Utility helpers for the fileserver implementation (framework-agnostic)."""

# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Iterable

LOG = logging.getLogger(__name__)

CHUNK_READ_SIZE = 8 * 1024 * 1024


class BadRequestError(Exception):
    """Raised when a client input is invalid."""

    pass


def get_snap_common() -> Path:
    """Return the snap's persistent data directory."""
    snap_common = os.environ.get("SNAP_COMMON")
    return Path(snap_common)


def uploads_root() -> Path:
    """Return (and ensure) the root directory for upload sessions."""
    root = get_snap_common() / "uploads"
    root.mkdir(parents=True, exist_ok=True)
    return root


def write_meta_json(directory: Path, data: Dict[str, Any]) -> None:
    """Write upload metadata to meta.json in the given directory."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "meta.json").write_text(json.dumps(data), encoding="utf-8")


def read_meta_json(directory: Path) -> Dict[str, Any]:
    """Read and parse meta.json from the given directory.

    Raises BadRequestError when missing or invalid.
    """
    meta_path = directory / "meta.json"
    if not meta_path.exists():
        raise BadRequestError("upload metadata missing")
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BadRequestError(f"invalid upload metadata: {exc}")


def assemble_chunks_to_file(chunk_paths: Iterable[Path], destination: Path) -> None:
    """Concatenate all chunk files into the destination in order."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with open(destination, "wb") as out:
        for c in chunk_paths:
            _copy_file_streaming(c, out)


def compute_sha256(path: Path) -> str:
    """Compute a streaming SHA-256 digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_READ_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def cleanup_upload(upload_dir: Path) -> None:
    """Best-effort removal of upload session artifacts.

    Removes chunk files, the chunks directory, metadata, and the session
    directory itself. All operations are best-effort.
    """
    _remove_chunk_files(upload_dir / "chunks")
    _remove_file_quietly(upload_dir / "meta.json")
    _rmdir_quietly(upload_dir / "chunks")
    _rmdir_quietly(upload_dir)


def _copy_file_streaming(src_path: Path, out_fp) -> None:
    """Copy a file into an already-opened binary file-like object."""
    with open(src_path, "rb") as inp:
        for buf in iter(lambda: inp.read(CHUNK_READ_SIZE), b""):
            out_fp.write(buf)


def _remove_chunk_files(chunks_dir: Path) -> None:
    if not chunks_dir.exists():
        return
    for p in chunks_dir.glob("*.part"):
        _remove_file_quietly(p)


def _remove_file_quietly(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except Exception as exc:
        LOG.warning("Failed to remove file %s: %s", path, exc)


def _rmdir_quietly(path: Path) -> None:
    try:
        path.rmdir()
    except Exception as exc:
        LOG.warning("Failed to remove directory %s: %s", path, exc)
