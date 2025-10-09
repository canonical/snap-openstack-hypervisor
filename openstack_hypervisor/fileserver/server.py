"""FastAPI server backing the remote file transfer service."""

# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0
import os
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from .utils import (
    CHUNK_READ_SIZE,
    assemble_chunks_to_file,
    atomic_replace,
    cleanup_upload,
    compute_sha256,
    read_meta_json,
    uploads_root,
    write_meta_json,
)


class CreatePathRequest(BaseModel):
    """Request body for path-creation endpoints."""

    dst_path: str


class UploadInitRequest(BaseModel):
    """Request body for initializing an upload session."""

    destination_path: str
    total_size: Optional[int] = None
    checksum: Optional[str] = None
    compression: Optional[str] = None


class FinalizeRequest(BaseModel):
    """Request body for finalizing an upload session."""

    upload_id: str


async def healthz_ep():
    """Return a simple health status payload."""
    return {"status": "ok"}


async def create_file_ep(body: CreatePathRequest):
    """Create an empty file at the provided destination path."""
    dst = Path(body.dst_path)
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(dst, "xb"):
            pass
    except FileExistsError:
        pass
    return {"created": True, "path": str(dst)}


async def remove_file_ep(dst_path: str):
    """Remove the file at the provided destination path."""
    dst = Path(dst_path)
    try:
        Path(dst).unlink(missing_ok=True)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return {"removed": True, "path": str(dst)}


async def create_dir_ep(body: CreatePathRequest):
    """Create a directory (and parents) at the provided path."""
    dst = Path(body.dst_path)
    Path(dst).mkdir(parents=True, exist_ok=True)
    return {"created": True, "path": str(dst)}


async def remove_dir_ep(dst_path: str):
    """Remove an empty directory at the provided path."""
    dst = Path(dst_path)
    try:
        Path(dst).rmdir()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return {"removed": True, "path": str(dst)}


async def upload_init_ep(body: UploadInitRequest):
    """Initialize a new upload session and return its ID."""
    dest = Path(body.destination_path)

    upload_id = uuid.uuid4().hex
    uroot = uploads_root() / upload_id
    (uroot / "chunks").mkdir(parents=True, exist_ok=True)
    comp_mode = (body.compression or "none").lower()
    if comp_mode not in ("none", "gzip"):
        raise HTTPException(status_code=400, detail="unsupported compression mode")
    write_meta_json(
        uroot,
        {
            "destination_path": str(dest),
            "total_size": body.total_size,
            "checksum": body.checksum,
            "compression": comp_mode,
        },
    )
    return {"upload_id": upload_id}


async def upload_chunk_ep(upload_id: str, request: Request, chunk_index: int, total_chunks: int):
    """Receive and store a single chunk for the given upload session."""
    uroot = uploads_root() / upload_id
    if not uroot.exists():
        raise HTTPException(status_code=404, detail="upload_id not found")
    meta = read_meta_json(uroot)

    chunk_path = uroot / "chunks" / f"{chunk_index:08d}.part"
    comp_mode = (meta.get("compression") or "none").lower()
    if comp_mode == "gzip":
        import gzip

        body = await request.body()
        try:
            data = gzip.decompress(body)
        except OSError as exc:
            raise HTTPException(status_code=400, detail=f"gzip decompress failed: {exc}")
        with open(chunk_path, "wb") as f:
            f.write(data)
    else:
        with open(chunk_path, "wb") as f:
            async for chunk in request.stream():
                f.write(chunk)
    return {"received": True, "chunk_index": chunk_index, "total_chunks": total_chunks}


async def upload_finalize_ep(body: FinalizeRequest):
    """Assemble uploaded chunks, validate, atomically place the final file."""
    uroot = uploads_root() / body.upload_id
    if not uroot.exists():
        raise HTTPException(status_code=404, detail="upload_id not found")
    meta = read_meta_json(uroot)
    dest = Path(meta["destination_path"])
    dest.parent.mkdir(parents=True, exist_ok=True)

    temp_path = dest.with_suffix(dest.suffix + ".tmp")
    chunks_dir = uroot / "chunks"
    chunk_files = sorted(chunks_dir.glob("*.part"))
    if not chunk_files:
        raise HTTPException(status_code=400, detail="no chunks uploaded")
    assemble_chunks_to_file(chunk_files, temp_path)

    if meta.get("total_size") is not None:
        if temp_path.stat().st_size != int(meta["total_size"]):
            raise HTTPException(status_code=400, detail="size mismatch")
    if meta.get("checksum"):
        if compute_sha256(temp_path) != meta["checksum"]:
            raise HTTPException(status_code=400, detail="checksum mismatch")

    atomic_replace(temp_path, dest)

    cleanup_upload(uroot)

    return {"finalized": True, "path": str(dest)}


async def download_file_ep(path: str):
    """Stream the requested file to the client."""
    src = Path(path)
    if not src.exists() or not src.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    def iterfile():
        with open(src, "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_READ_SIZE), b""):
                yield chunk

    headers = {
        "Content-Length": str(src.stat().st_size),
        "Content-Type": "application/octet-stream",
    }
    return StreamingResponse(iterfile(), headers=headers)


def create_app() -> FastAPI:
    """Create and return the FastAPI application."""
    app = FastAPI(title="OpenStack Hypervisor File Server", version="1.0.0")

    app.add_api_route("/healthz", healthz_ep, methods=["GET"])

    app.add_api_route("/fs/create-file", create_file_ep, methods=["POST"])
    app.add_api_route("/fs/remove-file", remove_file_ep, methods=["DELETE"])
    app.add_api_route("/fs/create-dir", create_dir_ep, methods=["POST"])
    app.add_api_route("/fs/remove-dir", remove_dir_ep, methods=["DELETE"])

    app.add_api_route("/upload/init", upload_init_ep, methods=["POST"])
    app.add_api_route("/upload/{upload_id}", upload_chunk_ep, methods=["PUT"])
    app.add_api_route("/upload/finalize", upload_finalize_ep, methods=["POST"])

    app.add_api_route("/download", download_file_ep, methods=["GET"])

    return app


if __name__ == "__main__":
    """Run the fileserver using uvicorn with default host/port."""
    import uvicorn

    host = os.environ.get("FILESERVER_HOST", "0.0.0.0")
    port = int(os.environ.get("FILESERVER_PORT", "8099"))
    uvicorn.run(create_app(), host=host, port=port, log_level="info")
