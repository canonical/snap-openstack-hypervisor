# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import importlib.machinery
import importlib.util
import json
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

SCRIPT = Path(__file__).parents[2] / "bin" / "pre-evacuation-setup-service"


class FakeClock:
    def __init__(self):
        self.start = 1000.0
        self.now = self.start

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds

    @property
    def elapsed(self):
        return self.now - self.start


@pytest.fixture
def svc(tmp_path, monkeypatch):
    """Load the pre-evacuation-setup-service script as a module, with SNAP_DATA in tmp_path."""
    monkeypatch.setenv("SNAP_DATA", str(tmp_path))
    # Do not write bytecode next to the script: bin/ is packaged into the snap.
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    loader = importlib.machinery.SourceFileLoader("pre_evacuation_setup_service", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)

    # Virtual time: sleeping advances the clock instantly, so retry and wait loops
    # run in microseconds and their durations can be asserted.
    clock = FakeClock()
    monkeypatch.setattr(module.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(module.time, "sleep", clock.sleep)
    module.clock = clock
    return module


def _message(status):
    return {"version": "1.0", "timestamp": 1.0, "status": status}


def _service(active):
    service = MagicMock()
    service.active = active
    return service


def _fake_snap(monkeypatch, svc, services):
    snap = MagicMock()
    snap.services.list.return_value = services
    monkeypatch.setattr(svc, "Snap", lambda: snap)
    return snap


class TestProtocol:
    def test_nic_up_is_a_valid_status(self, svc):
        message = svc.NetworkStatusMessage.model_validate(_message("nic-up"))
        assert message.status == "nic-up"

    def test_unknown_status_is_rejected(self, svc):
        with pytest.raises(ValueError):
            svc.NetworkStatusMessage.model_validate(_message("nic-sideways"))


class TestState:
    def test_load_state_missing(self, svc):
        assert svc.load_state() is None

    def test_save_and_load_state(self, svc):
        svc.save_state({"nova_compute_stopped": True})
        assert svc.load_state() == {"nova_compute_stopped": True}

    def test_clear_state(self, svc):
        svc.save_state({"nova_compute_stopped": True})
        svc.clear_state()
        svc.clear_state()  # clearing twice is fine
        assert svc.load_state() is None

    def test_corrupt_state_is_treated_as_nova_compute_stopped(self, svc, tmp_path):
        (tmp_path / svc.STATE_FILENAME).write_text("{not json")
        state = svc.load_state()
        assert state["nova_compute_stopped"] is True


class TestNicDown:
    @pytest.fixture(autouse=True)
    def _actions(self, svc, monkeypatch):
        self.stop = MagicMock()
        self.shutdown = MagicMock()
        monkeypatch.setattr(svc, "stop_nova_compute", self.stop)
        monkeypatch.setattr(svc, "shutdown_vms", self.shutdown)

    def test_records_state_then_stops_and_shuts_down(self, svc, monkeypatch):
        _fake_snap(monkeypatch, svc, {"nova-compute": _service(True)})

        response = json.loads(svc.handle_network_status(_message("nic-down")))

        assert response["status"] == "success"
        self.stop.assert_called_once()
        self.shutdown.assert_called_once()
        assert svc.load_state()["nova_compute_stopped"] is True

    def test_state_is_saved_before_nova_compute_is_stopped(self, svc, monkeypatch):
        _fake_snap(monkeypatch, svc, {"nova-compute": _service(True)})
        seen = {}
        self.stop.side_effect = lambda: seen.update(state=svc.load_state())

        svc.handle_network_status(_message("nic-down"))

        assert seen["state"] is not None

    def test_nova_compute_already_stopped_is_recorded_as_not_ours(self, svc, monkeypatch):
        _fake_snap(monkeypatch, svc, {"nova-compute": _service(False)})

        svc.handle_network_status(_message("nic-down"))

        assert svc.load_state()["nova_compute_stopped"] is False

    def test_repeated_nic_down_is_ignored_and_keeps_original_state(self, svc, monkeypatch):
        snap = _fake_snap(monkeypatch, svc, {"nova-compute": _service(True)})
        svc.handle_network_status(_message("nic-down"))
        # nova-compute is now down because of us: a second message must not rewrite
        # the state as "nova-compute was already stopped".
        snap.services.list.return_value = {"nova-compute": _service(False)}

        response = json.loads(svc.handle_network_status(_message("nic-down")))

        assert response["status"] == "success"
        assert self.stop.call_count == 1
        assert self.shutdown.call_count == 1
        assert svc.load_state()["nova_compute_stopped"] is True


class TestNicUp:
    @pytest.fixture(autouse=True)
    def _sync_thread(self, svc, monkeypatch):
        """Run the recovery thread inline so tests can assert on its result."""

        class InlineThread:
            def __init__(self, target, **kwargs):
                self.target = target

            def start(self):
                self.target()

        monkeypatch.setattr(svc.threading, "Thread", InlineThread)

    def test_nic_up_without_evacuation_does_nothing(self, svc, monkeypatch):
        start = MagicMock()
        monkeypatch.setattr(svc, "start_nova_compute", start)

        response = json.loads(svc.handle_network_status(_message("nic-up")))

        assert response["status"] == "success"
        assert "nothing to recover" in response["message"]
        start.assert_not_called()

    def test_nic_up_restarts_nova_compute_and_clears_state(self, svc, monkeypatch):
        svc.save_state({"nova_compute_stopped": True})
        start = MagicMock(return_value=True)
        monkeypatch.setattr(svc, "start_nova_compute", start)
        monkeypatch.setattr(svc, "host_in_maintenance", lambda snap: False)
        monkeypatch.setattr(svc, "Snap", MagicMock())

        response = json.loads(svc.handle_network_status(_message("nic-up")))

        assert response["message"] == "Recovery initiated"
        start.assert_called_once()
        assert svc.load_state() is None

    def test_nic_up_does_not_start_what_it_did_not_stop(self, svc, monkeypatch):
        svc.save_state({"nova_compute_stopped": False})
        start = MagicMock()
        monkeypatch.setattr(svc, "start_nova_compute", start)
        monkeypatch.setattr(svc, "host_in_maintenance", lambda snap: False)
        monkeypatch.setattr(svc, "Snap", MagicMock())

        svc.handle_network_status(_message("nic-up"))

        start.assert_not_called()
        assert svc.load_state() is None

    def test_nic_up_leaves_host_in_maintenance_alone(self, svc, monkeypatch):
        svc.save_state({"nova_compute_stopped": True})
        start = MagicMock()
        monkeypatch.setattr(svc, "start_nova_compute", start)
        monkeypatch.setattr(svc, "host_in_maintenance", lambda snap: True)
        monkeypatch.setattr(svc, "Snap", MagicMock())

        svc.handle_network_status(_message("nic-up"))

        start.assert_not_called()
        assert svc.load_state() is not None

    def test_failed_start_keeps_state_for_retry(self, svc, monkeypatch):
        svc.save_state({"nova_compute_stopped": True})
        start = MagicMock(return_value=False)
        monkeypatch.setattr(svc, "start_nova_compute", start)
        monkeypatch.setattr(svc, "host_in_maintenance", lambda snap: False)
        monkeypatch.setattr(svc, "Snap", MagicMock())

        svc.handle_network_status(_message("nic-up"))

        assert start.call_count == svc.NOVA_COMPUTE_START_ATTEMPTS
        assert svc.load_state() is not None

    def test_start_is_retried_until_it_succeeds(self, svc, monkeypatch):
        svc.save_state({"nova_compute_stopped": True})
        start = MagicMock(side_effect=[False, False, True])
        monkeypatch.setattr(svc, "start_nova_compute", start)
        monkeypatch.setattr(svc, "host_in_maintenance", lambda snap: False)
        monkeypatch.setattr(svc, "Snap", MagicMock())

        svc.handle_network_status(_message("nic-up"))

        assert start.call_count == 3
        assert svc.clock.elapsed == 2 * svc.NOVA_COMPUTE_START_RETRY_DELAY
        assert svc.load_state() is None

    def test_no_delay_after_the_last_failed_attempt(self, svc, monkeypatch):
        monkeypatch.setattr(svc, "start_nova_compute", MagicMock(return_value=False))

        assert svc.start_nova_compute_with_retries() is False

        delays = svc.NOVA_COMPUTE_START_ATTEMPTS - 1
        assert svc.clock.elapsed == delays * svc.NOVA_COMPUTE_START_RETRY_DELAY

    def test_concurrent_recovery_is_ignored(self, svc, monkeypatch):
        svc.save_state({"nova_compute_stopped": True})
        start = MagicMock()
        monkeypatch.setattr(svc, "start_nova_compute", start)
        assert svc._recovery_lock.acquire(blocking=False)
        try:
            svc.recover_node()
        finally:
            svc._recovery_lock.release()

        start.assert_not_called()
        assert svc.load_state() is not None


class TestStartNovaCompute:
    def test_already_active(self, svc, monkeypatch):
        service = _service(True)
        _fake_snap(monkeypatch, svc, {"nova-compute": service})

        assert svc.start_nova_compute() is True
        service.start.assert_not_called()

    def test_starts_and_waits_until_stable(self, svc, monkeypatch):
        service = _service(False)
        service.start.side_effect = lambda: setattr(service, "active", True)
        _fake_snap(monkeypatch, svc, {"nova-compute": service})

        assert svc.start_nova_compute() is True

        service.start.assert_called_once()
        # It did not return on the first sight of "active"
        assert svc.clock.elapsed >= svc.NOVA_COMPUTE_STABLE_SECONDS

    def test_crash_looping_service_is_not_counted_as_started(self, svc, monkeypatch):
        """A service that is active only between crashes must not count as started."""
        service = _service(False)
        snap = _fake_snap(monkeypatch, svc, {"nova-compute": service})
        polls = iter(range(10**6))

        def flapping():
            return {"nova-compute": _service(next(polls) % 2 == 1)}

        snap.services.list.side_effect = flapping

        assert svc.start_nova_compute() is False

    def test_missing_service(self, svc, monkeypatch):
        _fake_snap(monkeypatch, svc, {})
        assert svc.start_nova_compute() is False

    def test_times_out(self, svc, monkeypatch):
        service = _service(False)
        _fake_snap(monkeypatch, svc, {"nova-compute": service})
        monkeypatch.setattr(svc, "NOVA_COMPUTE_START_TIMEOUT", 0)

        assert svc.start_nova_compute() is False


class TestHostInMaintenance:
    def test_returns_masakari_answer(self, svc, monkeypatch):
        monkeypatch.setattr(svc, "masakari_host_on_maintenance", lambda snap: True)
        assert svc.host_in_maintenance(MagicMock()) is True

    def test_retries_until_masakari_answers(self, svc, monkeypatch):
        answers = iter([None, None, False])
        monkeypatch.setattr(svc, "masakari_host_on_maintenance", lambda snap: next(answers))

        assert svc.host_in_maintenance(MagicMock()) is False
        assert svc.clock.elapsed == 2 * svc.MAINTENANCE_LOOKUP_DELAY

    def test_assumes_not_in_maintenance_when_masakari_never_answers(self, svc, monkeypatch):
        calls = []
        monkeypatch.setattr(
            svc, "masakari_host_on_maintenance", lambda snap: calls.append(1) or None
        )

        assert svc.host_in_maintenance(MagicMock()) is False

        assert len(calls) > 1
        # bounded: never waits longer than the budget
        assert svc.clock.elapsed <= svc.MAINTENANCE_LOOKUP_BUDGET

    def test_a_hung_lookup_cannot_block_recovery(self, svc, monkeypatch):
        """A call that never returns is abandoned instead of hanging forever."""
        release = threading.Event()
        monkeypatch.setattr(svc, "masakari_host_on_maintenance", lambda snap: release.wait())
        monkeypatch.setattr(svc, "MASAKARI_ATTEMPT_TIMEOUT", 0.05)
        monkeypatch.setattr(svc, "MAINTENANCE_LOOKUP_BUDGET", 0)

        try:
            assert svc.host_in_maintenance(MagicMock()) is False
        finally:
            release.set()

    def test_call_with_timeout_returns_value(self, svc):
        assert svc._call_with_timeout(lambda: "ok", 1) == "ok"

    def test_call_with_timeout_swallows_errors(self, svc):
        def boom():
            raise RuntimeError("api down")

        assert svc._call_with_timeout(boom, 1) is None


class TestListenerResilience:
    def test_send_ignores_a_client_that_hung_up(self, svc):
        conn = MagicMock()
        conn.sendall.side_effect = BrokenPipeError(32, "Broken pipe")

        svc._send(conn, "reply")  # must not raise

    def test_handle_connection_survives_broken_pipe_on_reply(self, svc, monkeypatch):
        conn = MagicMock()
        conn.recv.return_value = json.dumps(_message("nic-up")).encode()
        conn.sendall.side_effect = BrokenPipeError(32, "Broken pipe")
        monkeypatch.setattr(svc, "handle_network_status", lambda data: "{}")

        svc._handle_connection(conn)  # must not raise

    def test_handle_connection_survives_broken_pipe_on_error_reply(self, svc):
        conn = MagicMock()
        conn.recv.return_value = b"not json"
        conn.sendall.side_effect = BrokenPipeError(32, "Broken pipe")

        svc._handle_connection(conn)  # must not raise

    def test_handle_connection_answers_a_valid_message(self, svc, monkeypatch):
        conn = MagicMock()
        conn.recv.return_value = json.dumps(_message("nic-up")).encode()
        monkeypatch.setattr(svc, "handle_network_status", lambda data: '{"status": "success"}')

        svc._handle_connection(conn)

        conn.sendall.assert_called_once_with(b'{"status": "success"}')

    def test_handle_connection_reports_invalid_status(self, svc):
        conn = MagicMock()
        conn.recv.return_value = json.dumps(_message("nic-sideways")).encode()

        svc._handle_connection(conn)

        reply = json.loads(conn.sendall.call_args[0][0].decode())
        assert reply["status"] == "error"


class TestMasakariLookup:
    @pytest.fixture
    def snap(self, tmp_path):
        snap = MagicMock()
        snap.paths.common = tmp_path
        snap.config.get.return_value = "compute-1.maas"
        snap.config.get_options.return_value.as_dict.return_value = {
            "identity": {
                "auth-url": "http://keystone/v3",
                "username": "u",
                "password": "p",
                "project-name": "services",
                "user-domain-name": "service_domain",
                "project-domain-name": "service_domain",
                "region-name": "RegionOne",
            }
        }
        return snap

    @pytest.fixture
    def conn(self, monkeypatch):
        conn = MagicMock()
        fake_openstack = MagicMock()
        fake_openstack.connect.return_value = conn
        monkeypatch.setitem(sys.modules, "openstack", fake_openstack)
        return conn

    @staticmethod
    def _host(name, on_maintenance):
        host = MagicMock()
        host.name = name
        host.on_maintenance = on_maintenance
        return host

    def test_host_on_maintenance(self, svc, snap, conn):
        conn.instance_ha.segments.return_value = [MagicMock(uuid="s1")]
        conn.instance_ha.hosts.return_value = [self._host("compute-1.maas", True)]
        assert svc.masakari_host_on_maintenance(snap) is True

    def test_requests_have_a_timeout(self, svc, snap, conn):
        import sys

        conn.instance_ha.segments.return_value = []
        svc.masakari_host_on_maintenance(snap)

        kwargs = sys.modules["openstack"].connect.call_args.kwargs
        assert kwargs["api_timeout"] == svc.MASAKARI_API_TIMEOUT

    def test_host_not_on_maintenance(self, svc, snap, conn):
        conn.instance_ha.segments.return_value = [MagicMock(uuid="s1")]
        conn.instance_ha.hosts.return_value = [self._host("compute-1.maas", False)]
        assert svc.masakari_host_on_maintenance(snap) is False

    def test_matches_short_hostname(self, svc, snap, conn):
        conn.instance_ha.segments.return_value = [MagicMock(uuid="s1")]
        conn.instance_ha.hosts.return_value = [self._host("compute-1", True)]
        assert svc.masakari_host_on_maintenance(snap) is True

    def test_does_not_match_a_different_host(self, svc, snap, conn):
        conn.instance_ha.segments.return_value = [MagicMock(uuid="s1")]
        conn.instance_ha.hosts.return_value = [self._host("compute-10.maas", True)]
        assert svc.masakari_host_on_maintenance(snap) is False

    def test_host_not_registered(self, svc, snap, conn):
        conn.instance_ha.segments.return_value = []
        assert svc.masakari_host_on_maintenance(snap) is False

    def test_api_failure_is_unknown(self, svc, snap, conn):
        conn.instance_ha.segments.side_effect = RuntimeError("api down")
        assert svc.masakari_host_on_maintenance(snap) is None

    def test_missing_credentials_is_unknown(self, svc, snap, conn):
        snap.config.get_options.return_value.as_dict.return_value = {"identity": {}}
        assert svc.masakari_host_on_maintenance(snap) is None
