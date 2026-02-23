# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0
import base64
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from openstack_hypervisor.services import FileTransferService

_CERT = base64.b64encode(b"CERT").decode()
_KEY = base64.b64encode(b"KEY").decode()
_CA = base64.b64encode(b"CA").decode()

_TLS_CONFIG = {
    "compute.cert": _CERT,
    "compute.key": _KEY,
    "compute.cacert": _CA,
}


@pytest.fixture
def tls_config(snap):
    """Wire snap.config.get to return valid base64 TLS data."""
    snap.config.get.side_effect = _TLS_CONFIG.get
    return snap


@pytest.fixture
def config_file(snap):
    """Create the webdav.conf that the service opens as FD 6."""
    path = Path(str(snap.paths.common)) / "etc" / "apache2" / "webdav.conf"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("ServerRoot /tmp\n")
    return path


class TestFileTransferService:
    """Tests for FileTransferService."""

    def test_returns_1_when_tls_not_configured(self, snap, config_file):
        """Service should return 1 when snap config has no TLS data."""
        snap.config.get.return_value = None
        result = FileTransferService().run(snap)
        assert result == 1

    def test_returns_1_when_tls_invalid_base64(self, snap, config_file):
        """Service should return 1 when TLS config value is not valid base64."""
        snap.config.get.return_value = "not-valid-base64!!!"
        result = FileTransferService().run(snap)
        assert result == 1

    @patch("openstack_hypervisor.services.os.open", side_effect=FileNotFoundError("no config"))
    @patch("openstack_hypervisor.services.os.set_inheritable")
    @patch("openstack_hypervisor.services.os.lseek")
    @patch("openstack_hypervisor.services.os.write")
    @patch("openstack_hypervisor.services.os.memfd_create", return_value=[10, 11, 12])
    @patch("openstack_hypervisor.services.os.dup2")
    @patch("openstack_hypervisor.services.os.close")
    def test_returns_1_when_config_missing(
        self, _close, _dup2, _memfd, _write, _lseek, _set_inh, _os_open, tls_config
    ):
        """Service should return 1 when webdav.conf cannot be opened."""
        result = FileTransferService().run(tls_config)
        assert result == 1

    @patch("openstack_hypervisor.services.subprocess.run")
    @patch("openstack_hypervisor.services.os.close")
    @patch("openstack_hypervisor.services.os.dup2")
    @patch("openstack_hypervisor.services.os.open", return_value=10)
    @patch("openstack_hypervisor.services.os.set_inheritable")
    @patch("openstack_hypervisor.services.os.lseek")
    @patch("openstack_hypervisor.services.os.write")
    @patch("openstack_hypervisor.services.os.memfd_create", return_value=[10, 11, 12])
    def test_success_path(
        self,
        mock_memfd,
        mock_write,
        mock_lseek,
        mock_set_inh,
        mock_os_open,
        mock_dup2,
        mock_close,
        mock_run,
        tls_config,
        config_file,
    ):
        """Service should create memfds from config, open config file, exec Apache."""
        mock_run.return_value = MagicMock(returncode=0)

        result = FileTransferService().run(tls_config)

        assert result == 0

        # Three memfds: cert, key, ca — in that order
        assert mock_memfd.call_count == 3
        assert [c.args[0] for c in mock_memfd.call_args_list] == ["cert", "key", "ca"]

        # Each memfd written, seeked back, marked inheritable; config FD also marked
        assert mock_write.call_count == 3
        assert mock_lseek.call_count == 3
        assert mock_set_inh.call_count == 4

        # Config opened with os.open
        mock_os_open.assert_called_once_with(str(config_file), os.O_RDONLY)

        # subprocess called with all four FDs
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args
        assert call_kwargs.kwargs["pass_fds"] == (3, 4, 5, 6)

        # Env vars
        env = call_kwargs.kwargs["env"]
        assert env["APACHE_RUN_DIR"] == str(tls_config.paths.common / "run" / "apache2")
        assert env["APACHE_LOG_DIR"] == str(tls_config.paths.common / "log" / "apache2")
        assert env["APACHE_PID_FILE"] == str(
            tls_config.paths.common / "run" / "apache2" / "apache2.pid"
        )
        assert env["APACHE_LOCK_DIR"] == str(tls_config.paths.common / "run" / "apache2")
        assert env["LANG"] == "C.UTF-8"
        assert env["LC_ALL"] == "C.UTF-8"

        # Command structure
        cmd = call_kwargs.args[0]
        assert cmd[0] == "/usr/bin/setpriv"
        assert "--reuid" in cmd
        assert "snap_daemon" in cmd
        assert "--regid" in cmd
        # Apache binary comes immediately after the "--" separator
        sep = cmd.index("--")
        assert cmd[sep + 1] == str(tls_config.paths.snap / "usr" / "sbin" / "apache2")
        assert cmd[-1] == "-DFOREGROUND"
        assert "/proc/self/fd/6" in cmd
