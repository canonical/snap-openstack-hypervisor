# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import gzip
import json
from pathlib import Path

import pytest
from webob import Request

from openstack_hypervisor.fileserver.server import application

API_PREFIX = "/v1"


def _call_app(method: str, path: str, body: bytes | None = None, query: dict | None = None):
    """Helper to invoke the WSGI application with a Request.

    Sets content-type to application/json when a body is provided.
    """
    if query:
        qs = "&".join(f"{k}={v}" for k, v in query.items())
        full_path = f"{path}?{qs}"
    else:
        full_path = path
    req = Request.blank(full_path, method=method)
    if body is not None:
        req.body = body
        req.content_type = "application/json"
    return req.get_response(application)


def test_healthz():
    resp = _call_app("GET", "/healthz")
    assert resp.status_int == 200
    payload = json.loads(resp.text)
    assert payload["status"] == "ok"


def test_create_and_remove_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SNAP_COMMON", str(tmp_path))
    dst = tmp_path / "testfile.bin"

    resp = _call_app(
        "POST",
        f"{API_PREFIX}/fs/create-file",
        body=json.dumps({"dst_path": str(dst)}).encode(),
    )
    assert resp.status_int == 200
    assert dst.exists()

    resp = _call_app("DELETE", f"{API_PREFIX}/fs/remove-file", query={"dst_path": str(dst)})
    assert resp.status_int == 200
    assert not dst.exists()


def test_create_and_remove_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SNAP_COMMON", str(tmp_path))
    d = tmp_path / "foo" / "bar"

    resp = _call_app(
        "POST",
        f"{API_PREFIX}/fs/create-dir",
        body=json.dumps({"dst_path": str(d)}).encode(),
    )
    assert resp.status_int == 200
    assert d.exists() and d.is_dir()

    resp = _call_app("DELETE", f"{API_PREFIX}/fs/remove-dir", query={"dst_path": str(d)})
    assert resp.status_int == 200
    assert not d.exists()


def test_upload_flow_gzip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    snap_common = tmp_path / "snap-common"
    snap_common.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("SNAP_COMMON", str(snap_common))

    destination = tmp_path / "final" / "file.img"
    data = b"hello world" * 4096

    resp = _call_app(
        "POST",
        f"{API_PREFIX}/upload/init",
        body=json.dumps(
            {
                "destination_path": str(destination),
                "total_size": len(data),
                "compression": "gzip",
            }
        ).encode(),
    )
    assert resp.status_int == 200
    upload_id = json.loads(resp.text)["upload_id"]

    gz_body = gzip.compress(data)
    req = Request.blank(
        f"{API_PREFIX}/upload/{upload_id}?chunk_index=0&total_chunks=1",
        method="PUT",
    )
    req.body = gz_body
    put_resp = req.get_response(application)
    assert put_resp.status_int == 200

    fin_resp = _call_app(
        "POST",
        f"{API_PREFIX}/upload/finalize",
        body=json.dumps({"upload_id": upload_id}).encode(),
    )
    assert fin_resp.status_int == 200
    assert destination.exists()
    assert destination.read_bytes() == data


def test_upload_finalize_checksum_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    snap_common = tmp_path / "snap-common"
    snap_common.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("SNAP_COMMON", str(snap_common))

    destination = tmp_path / "final" / "file.img"
    data = b"abcdef" * 1000

    resp = _call_app(
        "POST",
        f"{API_PREFIX}/upload/init",
        body=json.dumps(
            {
                "destination_path": str(destination),
                "total_size": len(data),
                "checksum": "deadbeef",
            }
        ).encode(),
    )
    assert resp.status_int == 200
    upload_id = json.loads(resp.text)["upload_id"]

    req = Request.blank(
        f"{API_PREFIX}/upload/{upload_id}?chunk_index=0&total_chunks=1",
        method="PUT",
    )
    req.body = data
    put_resp = req.get_response(application)
    assert put_resp.status_int == 200

    fin_resp = _call_app(
        "POST",
        f"{API_PREFIX}/upload/finalize",
        body=json.dumps({"upload_id": upload_id}).encode(),
    )
    assert fin_resp.status_int == 400
    payload = json.loads(fin_resp.text)
    assert "checksum mismatch" in payload["detail"]
