# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0
"""WSGI server for remote file transfer operations (threaded backend).

This module exposes a minimal WebOb-based WSGI application, typically
hosted with ``oslo_service.wsgi.Server``. It implements endpoints for
basic filesystem operations, chunked uploads (with optional gzip
compression), and file downloads. TLS support is configured via
``oslo_service.sslutils`` and ``oslo_config``.
"""

import errno
import gzip as _gzip
import json
import os
import ssl
import threading
import uuid
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Dict
from wsgiref.simple_server import WSGIServer, make_server

from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service, sslutils
from webob import Request, Response

from .utils import (
    CHUNK_READ_SIZE,
    BadRequestError,
    assemble_chunks_to_file,
    cleanup_upload,
    compute_sha256,
    get_snap_common,
    read_meta_json,
    uploads_root,
    write_meta_json,
)

LOG = logging.getLogger(__name__)


fileserver_opts = [
    cfg.StrOpt(
        "host",
        default=os.environ.get("FILESERVER_HOST", "0.0.0.0"),
        help="Listen address for the file server",
    ),
    cfg.IntOpt(
        "port",
        default=int(os.environ.get("FILESERVER_PORT", "8099")),
        min=1,
        help="TCP listen port for the file server",
    ),
    cfg.StrOpt(
        "sandbox_root",
        default=os.environ.get("SNAP_COMMON"),
        help="Base directory for sandboxed filesystem operations",
    ),
]

CONF = cfg.CONF
CONF.register_opts(fileserver_opts, group="fileserver")
sslutils.register_opts(CONF)


def _resolve_sandboxed_path(path_str: str) -> Path | None:
    """Resolve a user-supplied path within the sandbox (SNAP_COMMON).

    Returns an absolute Path when the path is within SNAP_COMMON. If
    SNAP_COMMON is not set, returns the raw path as-is (for tests/dev).
    Returns None if the resolved path escapes the sandbox.
    """
    base_str = os.environ.get("SNAP_COMMON") or CONF.fileserver.sandbox_root
    candidate = Path(path_str)
    if not base_str:
        return candidate
    base = Path(base_str).resolve()
    resolved = (candidate if candidate.is_absolute() else base / candidate).resolve()
    try:
        resolved.relative_to(base)
    except ValueError:
        return None
    return resolved


def _json(request: Request) -> Dict[str, Any]:
    """Parse JSON body into a dictionary.

    Returns an empty dict when the body is empty. Raises BadRequestError on
    invalid JSON.
    """
    if not request.body_file:
        return {}
    try:
        body = request.body
    except AttributeError:
        body = request.body_file.read()
    if not body:
        return {}
    try:
        return json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise BadRequestError(f"invalid JSON body: {exc}")


def _ok(payload: Dict[str, Any]) -> Response:
    """Return a JSON 200 OK response with the provided payload."""
    return Response(json_body=payload)


def _error(status: int, detail: str) -> Response:
    """Return a JSON error response with the given HTTP status and detail."""
    return Response(json_body={"detail": detail}, status=status)


def create_file_ep(request: Request) -> Response:
    """Create an empty file at the requested destination path."""
    try:
        payload = _json(request)
        dst_path = payload.get("dst_path")
        if not dst_path:
            raise BadRequestError("dst_path is required")
        dst = _resolve_sandboxed_path(dst_path)
        if dst is None:
            return _error(400, "path outside sandbox")
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(dst, "xb"):
                pass
        except FileExistsError:
            pass
        return _ok({"created": True, "path": str(dst)})
    except BadRequestError as exc:
        return _error(400, str(exc))
    except Exception as exc:
        LOG.exception("create_file failed: %s", exc)
        return _error(500, str(exc))


def remove_file_ep(request: Request) -> Response:
    """Remove a file at the given destination path (if present)."""
    dst_path = request.GET.get("dst_path")
    if not dst_path:
        return _error(400, "dst_path is required")
    dst = _resolve_sandboxed_path(dst_path)
    if dst is None:
        return _error(400, "path outside sandbox")
    try:
        Path(dst).unlink(missing_ok=True)
        return _ok({"removed": True, "path": str(dst)})
    except Exception as exc:
        LOG.exception("remove_file failed: %s", exc)
        return _error(500, str(exc))


def create_dir_ep(request: Request) -> Response:
    """Create a directory (parents as needed) at the destination path."""
    try:
        payload = _json(request)
        dst_path = payload.get("dst_path")
        if not dst_path:
            raise BadRequestError("dst_path is required")
        dst = _resolve_sandboxed_path(dst_path)
        if dst is None:
            return _error(400, "path outside sandbox")
        Path(dst).mkdir(parents=True, exist_ok=True)
        return _ok({"created": True, "path": str(dst)})
    except BadRequestError as exc:
        return _error(400, str(exc))
    except Exception as exc:
        LOG.exception("create_dir failed: %s", exc)
        return _error(500, str(exc))


def remove_dir_ep(request: Request) -> Response:
    """Remove an empty directory at the destination path."""
    dst_path = request.GET.get("dst_path")
    if not dst_path:
        return _error(400, "dst_path is required")
    dst = _resolve_sandboxed_path(dst_path)
    if dst is None:
        return _error(400, "path outside sandbox")
    try:
        Path(dst).rmdir()
        return _ok({"removed": True, "path": str(dst)})
    except OSError as exc:
        if exc.errno in (errno.ENOTEMPTY, errno.EEXIST):
            return _error(409, "directory not empty")
        LOG.exception("remove_dir failed: %s", exc)
        return _error(500, str(exc))


def upload_init_ep(request: Request) -> Response:
    """Initialize a new upload session and return its identifier."""
    try:
        payload = _json(request)
        destination_path = payload.get("destination_path")
        if not destination_path:
            raise BadRequestError("destination_path is required")
        total_size = payload.get("total_size")
        checksum = payload.get("checksum")
        comp_mode = (payload.get("compression") or "none").lower()
        if comp_mode not in ("none", "gzip"):
            raise BadRequestError("unsupported compression mode")

        dest = Path(destination_path)
        upload_id = uuid.uuid4().hex
        uroot = uploads_root() / upload_id
        (uroot / "chunks").mkdir(parents=True, exist_ok=True)
        write_meta_json(
            uroot,
            {
                "destination_path": str(dest),
                "total_size": total_size,
                "checksum": checksum,
                "compression": comp_mode,
            },
        )
        return _ok({"upload_id": upload_id})
    except BadRequestError as exc:
        return _error(400, str(exc))
    except Exception as exc:
        LOG.exception("upload_init failed: %s", exc)
        return _error(500, str(exc))


def upload_chunk_ep(
    request: Request, upload_id: str, chunk_index: int, total_chunks: int
) -> Response:
    """Receive and persist a single upload chunk for the given session."""
    uroot = uploads_root() / upload_id
    if not uroot.exists():
        return _error(404, "upload_id not found")
    try:
        meta = read_meta_json(uroot)
    except BadRequestError as exc:
        return _error(400, str(exc))

    chunk_path = uroot / "chunks" / f"{chunk_index:08d}.part"
    comp_mode = (meta.get("compression") or "none").lower()
    try:
        if comp_mode == "gzip":
            body = request.body_file.read()
            data = _gzip.decompress(body)
            with open(chunk_path, "wb") as f:
                f.write(data)
        else:
            with open(chunk_path, "wb") as f:
                buf = request.body_file.read(CHUNK_READ_SIZE)
                while buf:
                    f.write(buf)
                    buf = request.body_file.read(CHUNK_READ_SIZE)
        return _ok({"received": True, "chunk_index": chunk_index, "total_chunks": total_chunks})
    except OSError as exc:
        return _error(400, f"gzip decompress failed: {exc}")
    except Exception as exc:
        LOG.exception("upload_chunk failed: %s", exc)
        return _error(500, str(exc))


def upload_finalize_ep(request: Request) -> Response:  # noqa: C901
    """Finalize an upload by assembling chunks and performing validations."""
    try:
        payload = _json(request)
        upload_id = payload.get("upload_id")
        if not upload_id:
            raise BadRequestError("upload_id is required")
        uroot = uploads_root() / upload_id
        if not uroot.exists():
            return _error(404, "upload_id not found")
        meta = read_meta_json(uroot)
        dest = Path(meta["destination_path"])
        dest.parent.mkdir(parents=True, exist_ok=True)

        temp_path = dest.with_suffix(dest.suffix + ".tmp")
        chunks_dir = uroot / "chunks"
        chunk_files = sorted(chunks_dir.glob("*.part"))
        if not chunk_files:
            return _error(400, "no chunks uploaded")
        assemble_chunks_to_file(chunk_files, temp_path)

        if meta.get("total_size") is not None:
            if temp_path.stat().st_size != int(meta["total_size"]):
                return _error(400, "size mismatch")
        if meta.get("checksum"):
            if compute_sha256(temp_path) != meta["checksum"]:
                return _error(400, "checksum mismatch")

        os.replace(temp_path, dest)
        cleanup_upload(uroot)
        return _ok({"finalized": True, "path": str(dest)})
    except BadRequestError as exc:
        return _error(400, str(exc))
    except Exception as exc:
        LOG.exception("upload_finalize failed: %s", exc)
        return _error(500, str(exc))


def upload_abort_ep(request: Request) -> Response:
    """Abort an in-flight upload and cleanup its temporary files."""
    try:
        payload = _json(request)
        upload_id = payload.get("upload_id")
        if not upload_id:
            raise BadRequestError("upload_id is required")
        uroot = uploads_root() / upload_id
        if not uroot.exists():
            return _ok({"aborted": False, "detail": "not found"})
        cleanup_upload(uroot)
        return _ok({"aborted": True})
    except BadRequestError as exc:
        return _error(400, str(exc))
    except Exception as exc:
        LOG.exception("upload_abort failed: %s", exc)
        return _error(500, str(exc))


API_PREFIX = "/v1"


def _route(request: Request) -> Response:  # noqa: C901
    """Dispatch incoming requests to the appropriate endpoint handler."""
    path = request.path_info or "/"
    if path == "/healthz" and request.method == "GET":
        return _ok({"status": "ok"})
    path = path[len(API_PREFIX) :] or "/"  # noqa: E203
    if path == "/fs/create-file" and request.method == "POST":
        return create_file_ep(request)
    if path == "/fs/remove-file" and request.method == "DELETE":
        return remove_file_ep(request)
    if path == "/fs/create-dir" and request.method == "POST":
        return create_dir_ep(request)
    if path == "/fs/remove-dir" and request.method == "DELETE":
        return remove_dir_ep(request)
    if path == "/upload/init" and request.method == "POST":
        return upload_init_ep(request)
    if path.startswith("/upload/") and request.method == "PUT":
        upload_id = path.split("/", 2)[2]
        try:
            chunk_index = int(request.GET.get("chunk_index", ""))
            total_chunks = int(request.GET.get("total_chunks", ""))
        except ValueError:
            return _error(400, "chunk_index and total_chunks must be integers")
        return upload_chunk_ep(request, upload_id, chunk_index, total_chunks)
    if path == "/upload/finalize" and request.method == "POST":
        return upload_finalize_ep(request)
    if path == "/upload/abort" and request.method == "POST":
        return upload_abort_ep(request)
    return _error(404, "Not found")


def application(environ, start_response):
    """WSGI application callable."""
    request = Request(environ)
    response = _route(request)
    return response(environ, start_response)


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """Threading-based WSGI server."""

    daemon_threads = True


class ThreadingWSGIService(service.ServiceBase):
    """Threading-based WSGI service."""

    def __init__(self, app, host: str, port: int, ssl_context: ssl.SSLContext | None):
        self._app = app
        self._host = host
        self._port = port
        self._ssl_context = ssl_context
        self._httpd = None
        self._thread = None

    def start(self):
        """Start the WSGI service."""
        self._httpd = make_server(
            self._host, self._port, self._app, server_class=ThreadingWSGIServer
        )
        if self._ssl_context is not None:
            self._httpd.socket = self._ssl_context.wrap_socket(
                self._httpd.socket, server_side=True
            )
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="fileserver", daemon=True
        )
        self._thread.start()

    def stop(self, graceful=True):
        """Stop the WSGI service."""
        if self._httpd is not None:
            self._httpd.shutdown()

    def wait(self):
        """Wait for the WSGI service to finish."""
        if self._thread is not None:
            self._thread.join()

    def reset(self, exiting=False):
        """Reset service state (no-op)."""
        return


if __name__ == "__main__":
    logging.register_options(CONF)
    logging.setup(CONF, "openstack_hypervisor.fileserver")
    default_cfg = str(get_snap_common() / "etc/nova/nova.conf")
    CONF(
        project="openstack-hypervisor",
        prog="openstack-hypervisor-fileserver",
        version="1.0.0",
        default_config_files=[default_cfg],
    )

    host = CONF.fileserver.host
    port = CONF.fileserver.port

    ssl_ctx = None
    if sslutils.is_enabled(CONF):
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(CONF.ssl.cert_file, CONF.ssl.key_file)
        ssl_ctx.load_verify_locations(CONF.ssl.ca_file)
        ssl_ctx.verify_mode = ssl.CERT_REQUIRED
        LOG.info("mTLS enabled for fileserver")
    else:
        LOG.info("TLS disabled for fileserver")

    service_obj = ThreadingWSGIService(application, host, port, ssl_ctx)
    launcher = service.ServiceLauncher(CONF)
    launcher.launch_service(service_obj, workers=1)
    launcher.wait()
