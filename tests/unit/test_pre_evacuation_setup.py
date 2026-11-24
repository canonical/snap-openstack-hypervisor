# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import importlib.machinery
import importlib.util
import json
import os
import stat
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


def _plant(svc, **fields):
    svc.save_state(fields)


def _state(svc):
    return svc.load_state()


def _join_recovery_thread(svc, timeout=5):
    """Wait for the recover-node thread spawned by handle_nic_up to finish."""
    for t in threading.enumerate():
        if t.name == "recover-node":
            t.join(timeout)


class InlineThread:
    """Run the thread target synchronously so tests can assert on its result."""

    def __init__(self, target, args=(), **kwargs):
        self.target = target
        self.args = args

    def start(self):
        self.target(*self.args)


class TestProtocol:
    def test_nic_up_is_a_valid_status(self, svc):
        message = svc.NetworkStatusMessage.model_validate(_message("nic-up"))
        assert message.status == "nic-up"

    def test_unknown_status_is_rejected(self, svc):
        with pytest.raises(ValueError):
            svc.NetworkStatusMessage.model_validate(_message("nic-sideways"))


class TestState:
    def test_corrupt_state_is_treated_as_nova_compute_stopped(self, svc, tmp_path):
        (tmp_path / svc.STATE_FILENAME).write_text("{not json")
        state = svc.load_state()
        assert state["nova_compute_stopped"] is True

    def test_corrupt_state_has_no_outage_generation(self, svc, tmp_path):
        """A corrupt record cannot be tied to an outage: it must re-fence as a new one."""
        (tmp_path / svc.STATE_FILENAME).write_text("{not json")
        assert "outage_generation" not in svc.load_state()


class TestNicDown:
    """Contract 1: the record tracks fencing steps; redelivery completes missing ones."""

    @pytest.fixture(autouse=True)
    def _actions(self, svc, monkeypatch):
        self.stop = MagicMock()
        self.shutdown = MagicMock()
        monkeypatch.setattr(svc, "stop_nova_compute", self.stop)
        monkeypatch.setattr(svc, "shutdown_vms", self.shutdown)

    def test_fresh_outage_records_generation_then_fences(self, svc, monkeypatch):
        _fake_snap(monkeypatch, svc, {"nova-compute": _service(True)})

        response = json.loads(svc.handle_network_status(_message("nic-down")))

        assert response["status"] == "success"
        self.stop.assert_called_once()
        self.shutdown.assert_called_once()
        state = _state(svc)
        assert state["nova_compute_stopped"] is True
        assert state["outage_generation"] == 1
        assert state["fencing_completed"] is True

    def test_state_is_saved_before_nova_compute_is_stopped(self, svc, monkeypatch):
        _fake_snap(monkeypatch, svc, {"nova-compute": _service(True)})
        seen = {}
        self.stop.side_effect = lambda: seen.update(state=_state(svc))

        svc.handle_network_status(_message("nic-down"))

        assert seen["state"] is not None

    def test_nova_already_stopped_is_recorded_as_not_ours(self, svc, monkeypatch):
        _fake_snap(monkeypatch, svc, {"nova-compute": _service(False)})

        svc.handle_network_status(_message("nic-down"))

        assert _state(svc)["nova_compute_stopped"] is False

    def test_redelivery_refences_and_retags_generation(self, svc, monkeypatch):
        snap = _fake_snap(monkeypatch, svc, {"nova-compute": _service(True)})
        svc.handle_network_status(_message("nic-down"))
        first = _state(svc)
        # nova-compute came back (recovery or operator): the redelivery must fence again.
        snap.services.list.return_value = {"nova-compute": _service(True)}

        response = json.loads(svc.handle_network_status(_message("nic-down")))

        assert response["status"] == "success"
        assert self.stop.call_count == 2
        assert self.shutdown.call_count == 2
        state = _state(svc)
        assert state["outage_generation"] == first["outage_generation"] + 1
        assert state["nova_compute_stopped"] is True
        assert state["fencing_completed"] is True

    def test_redelivery_preserves_owed_restart_when_nova_stays_down(self, svc, monkeypatch):
        _fake_snap(monkeypatch, svc, {"nova-compute": _service(True)})
        svc.handle_network_status(_message("nic-down"))
        _fake_snap(monkeypatch, svc, {"nova-compute": _service(False)})

        svc.handle_network_status(_message("nic-down"))

        # nova-compute never came back: recovery still owes the restart.
        assert _state(svc)["nova_compute_stopped"] is True

    def test_redelivery_cancels_a_pending_recovery(self, svc, monkeypatch):
        _fake_snap(monkeypatch, svc, {"nova-compute": _service(True)})
        svc.handle_network_status(_message("nic-down"))
        _plant(svc, recovery_requested=True, recovery_status="pending", recovery_cycles=1)
        _fake_snap(monkeypatch, svc, {"nova-compute": _service(False)})

        svc.handle_network_status(_message("nic-down"))

        state = _state(svc)
        assert state["recovery_requested"] is False
        assert "recovery_status" not in state
        assert state["recovery_cycles"] == 0

    def test_stale_record_from_an_older_outage_is_refenced(self, svc, monkeypatch):
        """A record without a generation tag (planted or pre-upgrade) must not suppress fencing."""
        _fake_snap(monkeypatch, svc, {"nova-compute": _service(True)})
        _plant(svc, timestamp=1.0, nova_compute_stopped=False, fencing_completed=True)

        svc.handle_network_status(_message("nic-down"))

        self.shutdown.assert_called_once()
        state = _state(svc)
        assert state["outage_generation"] == 1
        assert state["fencing_completed"] is True

    def test_failed_state_write_does_not_block_fencing(self, svc, monkeypatch):
        _fake_snap(monkeypatch, svc, {"nova-compute": _service(True)})
        saved = []

        def failing_save(state):
            saved.append(dict(state))
            raise OSError("disk full")

        monkeypatch.setattr(svc, "save_state", failing_save)

        response = json.loads(svc.handle_network_status(_message("nic-down")))

        assert response["status"] == "success"
        # Fencing ran although the bookkeeping write failed: the record never
        # landed, so the completion mark finds no record (a later nic-down will
        # re-fence from scratch).
        assert self.stop.call_count == 1
        assert self.shutdown.call_count == 1
        assert len(saved) == 1

    def test_each_nic_down_bumps_the_generation(self, svc, monkeypatch):
        _fake_snap(monkeypatch, svc, {"nova-compute": _service(False)})

        svc.handle_network_status(_message("nic-down"))
        assert svc._outage_generation == 1
        svc.handle_network_status(_message("nic-down"))
        assert svc._outage_generation == 2


class TestNicUp:
    """Contract 2: the nic-up ack means the recovery request is durably accepted."""

    @pytest.fixture(autouse=True)
    def _sync_thread(self, svc, monkeypatch):
        monkeypatch.setattr(svc.threading, "Thread", InlineThread)

    def test_nic_up_without_evacuation_does_nothing(self, svc, monkeypatch):
        worker = MagicMock()
        monkeypatch.setattr(svc, "_start_recovery_worker", worker)

        response = json.loads(svc.handle_network_status(_message("nic-up")))

        assert response["status"] == "success"
        assert "nothing to recover" in response["message"]
        worker.assert_not_called()

    def test_nic_up_persists_the_request_before_acking(self, svc, monkeypatch):
        svc.save_state({"outage_generation": 1, "nova_compute_stopped": True})
        worker = MagicMock()
        monkeypatch.setattr(svc, "_start_recovery_worker", worker)

        response = json.loads(svc.handle_network_status(_message("nic-up")))

        assert response["message"] == "Recovery initiated"
        state = _state(svc)
        assert state["recovery_requested"] is True
        assert state["recovery_status"] == "pending"
        assert state["recovery_cycles"] == 0
        worker.assert_called_once()

    def test_failed_persist_returns_error_and_starts_no_worker(self, svc, monkeypatch):
        """A request that cannot be made durable must not be acknowledged."""
        svc.save_state({"outage_generation": 1, "nova_compute_stopped": True})
        worker = MagicMock()
        monkeypatch.setattr(svc, "_start_recovery_worker", worker)
        monkeypatch.setattr(svc, "save_state", MagicMock(side_effect=OSError("disk full")))

        response = json.loads(svc.handle_network_status(_message("nic-up")))

        assert response["status"] == "error"
        worker.assert_not_called()

    def test_worker_drains_the_pending_request(self, svc, monkeypatch):
        """A nic-up arriving while a worker is busy is picked up, never dropped."""
        svc.save_state({"outage_generation": 1, "nova_compute_stopped": True})
        once = MagicMock(side_effect=lambda gen, state: svc.clear_state() or True)
        monkeypatch.setattr(svc, "_recover_once", once)

        svc.handle_network_status(_message("nic-up"))
        _join_recovery_thread(svc)

        once.assert_called_once()
        assert svc._recovery_running is False


class TestRecoveryOnce:
    def _run(self, svc, monkeypatch, state, maintenance, start=None):
        monkeypatch.setattr(svc, "host_in_maintenance", lambda snap, gen: maintenance)
        monkeypatch.setattr(svc, "Snap", MagicMock())
        if start is not None:
            monkeypatch.setattr(svc, "start_nova_compute_with_retries", start)
        return svc._recover_once(svc._outage_generation, state)

    def test_maintenance_defers_to_the_operator(self, svc, monkeypatch):
        _plant(svc, nova_compute_stopped=True, recovery_requested=True)
        result = self._run(svc, monkeypatch, _state(svc), True)

        assert result is False
        state = _state(svc)
        assert state["recovery_requested"] is False
        assert state["recovery_status"] == "deferred_maintenance"

    def test_unknown_maintenance_keeps_the_node_down(self, svc, monkeypatch):
        """Masakari unreachable after the budget: never restart, keep the request pending."""
        _plant(svc, nova_compute_stopped=True, recovery_requested=True)
        start = MagicMock()
        result = self._run(svc, monkeypatch, _state(svc), "unknown", start=start)

        assert result is False
        start.assert_not_called()
        state = _state(svc)
        assert state["recovery_requested"] is True
        assert state["recovery_status"] == "waiting_maintenance_status"

    def test_successful_start_clears_the_state(self, svc, monkeypatch):
        _plant(svc, nova_compute_stopped=True, recovery_requested=True)
        result = self._run(
            svc, monkeypatch, _state(svc), False, start=MagicMock(return_value=True)
        )

        assert result is True
        assert _state(svc) is None

    def test_failed_cycle_schedules_a_retry(self, svc, monkeypatch):
        _plant(svc, nova_compute_stopped=True, recovery_requested=True, recovery_cycles=0)
        result = self._run(
            svc, monkeypatch, _state(svc), False, start=MagicMock(return_value=False)
        )

        assert result is False
        state = _state(svc)
        assert state["recovery_requested"] is True
        assert state["recovery_status"] == "retry_scheduled"
        assert state["recovery_cycles"] == 1

    def test_cycle_cap_hands_over_to_the_operator(self, svc, monkeypatch):
        _plant(
            svc,
            nova_compute_stopped=True,
            recovery_requested=True,
            recovery_cycles=svc.MAX_RECOVERY_CYCLES - 1,
        )
        result = self._run(
            svc, monkeypatch, _state(svc), False, start=MagicMock(return_value=False)
        )

        assert result is False
        state = _state(svc)
        assert state["recovery_requested"] is False
        assert state["recovery_status"] == "failed"

    def test_cancellation_after_a_completed_start_undoes_it(self, svc, monkeypatch):
        stop = MagicMock()
        monkeypatch.setattr(svc, "stop_nova_compute", stop)
        _plant(svc, nova_compute_stopped=True, recovery_requested=True)

        def start_then_new_outage(gen):
            svc._cancel_pending_recovery()  # a newer nic-down arrives during the start
            return True

        result = self._run(svc, monkeypatch, _state(svc), False, start=start_then_new_outage)

        assert result is False
        stop.assert_called_once()
        assert _state(svc) is not None


class TestRecoveryWorkerAndSweeper:
    def test_worker_drains_until_the_state_is_gone(self, svc, monkeypatch):
        _plant(svc, nova_compute_stopped=True, recovery_requested=True)
        once = MagicMock(side_effect=lambda gen, state: svc.clear_state() or True)
        monkeypatch.setattr(svc, "_recover_once", once)

        svc._recovery_worker()

        assert once.call_count == 1
        assert svc._recovery_running is False

    def test_sweeper_relaunches_the_worker_for_a_pending_request(self, svc, monkeypatch):
        _plant(svc, nova_compute_stopped=True, recovery_requested=True)
        starter = MagicMock()
        monkeypatch.setattr(svc, "_start_recovery_worker", starter)
        sleeps = []

        def fake_sleep(seconds):
            sleeps.append(seconds)
            if len(sleeps) > 1:
                raise KeyboardInterrupt  # stop the infinite sweeper after one pass

        monkeypatch.setattr(svc.time, "sleep", fake_sleep)
        with pytest.raises(KeyboardInterrupt):
            svc._recovery_sweeper()

        starter.assert_called_once()

    def test_resume_on_startup_picks_up_a_pending_request(self, svc, monkeypatch):
        _plant(svc, nova_compute_stopped=True, recovery_requested=True)
        starter = MagicMock()
        monkeypatch.setattr(svc, "_start_recovery_worker", starter)

        svc.resume_pending_recovery()

        starter.assert_called_once()


class TestStartNovaCompute:
    def test_already_active_must_still_prove_stability(self, svc, monkeypatch):
        """A crash-looping service is briefly active between restarts: one sample is not enough."""
        service = _service(True)
        _fake_snap(monkeypatch, svc, {"nova-compute": service})

        assert svc.start_nova_compute(svc._outage_generation) is True
        service.start.assert_not_called()
        assert svc.clock.elapsed >= svc.NOVA_COMPUTE_STABLE_SECONDS

    def test_starts_and_waits_until_stable(self, svc, monkeypatch):
        service = _service(False)
        service.start.side_effect = lambda: setattr(service, "active", True)
        _fake_snap(monkeypatch, svc, {"nova-compute": service})

        assert svc.start_nova_compute(svc._outage_generation) is True

        service.start.assert_called_once()
        assert svc.clock.elapsed >= svc.NOVA_COMPUTE_STABLE_SECONDS

    def test_crash_looping_service_is_not_counted_as_started(self, svc, monkeypatch):
        service = _service(False)
        snap = _fake_snap(monkeypatch, svc, {"nova-compute": service})
        polls = iter(range(10**6))

        def flapping():
            return {"nova-compute": _service(next(polls) % 2 == 1)}

        snap.services.list.side_effect = flapping

        assert svc.start_nova_compute(svc._outage_generation) is False


class TestStartNovaComputeWithRetries:
    def test_retries_until_it_succeeds(self, svc, monkeypatch):
        start = MagicMock(side_effect=[False, False, True])
        monkeypatch.setattr(svc, "start_nova_compute", start)

        assert svc.start_nova_compute_with_retries(svc._outage_generation) is True
        assert start.call_count == 3
        assert svc.clock.elapsed == 2 * svc.NOVA_COMPUTE_START_RETRY_DELAY


class TestHostInMaintenance:
    def test_budget_exhaustion_fails_closed(self, svc, monkeypatch):
        """Masakari unreachable after the budget: 'unknown', never 'not in maintenance'."""
        monkeypatch.setattr(svc, "masakari_host_on_maintenance", lambda snap: None)

        assert svc.host_in_maintenance(MagicMock(), svc._outage_generation) == "unknown"
        assert svc.clock.elapsed <= svc.MAINTENANCE_LOOKUP_BUDGET

    def test_a_hung_lookup_cannot_block_recovery(self, svc, monkeypatch):
        release = threading.Event()
        monkeypatch.setattr(svc, "masakari_host_on_maintenance", lambda snap: release.wait())
        monkeypatch.setattr(svc, "MASAKARI_ATTEMPT_TIMEOUT", 0.05)
        monkeypatch.setattr(svc, "MAINTENANCE_LOOKUP_BUDGET", 0)

        try:
            assert svc.host_in_maintenance(MagicMock(), svc._outage_generation) == "unknown"
        finally:
            release.set()

    def test_cancellation_during_the_lookup(self, svc, monkeypatch):
        def bump_and_fail(snap):
            svc._cancel_pending_recovery()
            return None

        monkeypatch.setattr(svc, "masakari_host_on_maintenance", bump_and_fail)

        assert svc.host_in_maintenance(MagicMock(), svc._outage_generation) is None


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
                "region-name": "workload-region",
                "keystone-region-name": "keystone-region",
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

    def test_uses_the_workload_region_not_the_keystone_region(self, svc, snap, conn):
        import sys

        conn.instance_ha.segments.return_value = []
        svc.masakari_host_on_maintenance(snap)

        kwargs = sys.modules["openstack"].connect.call_args.kwargs
        assert kwargs["region_name"] == "workload-region"

    def test_disabled_nova_service_requires_operator_handoff(self, svc, snap, conn):
        """Masakari's host-failure workflow disables the Nova service: leave it alone."""
        nova_svc = MagicMock()
        nova_svc.host = "compute-1.maas"
        nova_svc.status = "disabled"
        conn.instance_ha.segments.return_value = [MagicMock(uuid="s1")]
        conn.instance_ha.hosts.return_value = [self._host("compute-1.maas", False)]
        conn.compute.services.return_value = [nova_svc]

        assert svc.masakari_host_on_maintenance(snap) is True

    def test_enabled_nova_service_is_not_maintenance(self, svc, snap, conn):
        nova_svc = MagicMock()
        nova_svc.host = "compute-1.maas"
        nova_svc.status = "enabled"
        conn.instance_ha.segments.return_value = [MagicMock(uuid="s1")]
        conn.instance_ha.hosts.return_value = [self._host("compute-1.maas", False)]
        conn.compute.services.return_value = [nova_svc]

        assert svc.masakari_host_on_maintenance(snap) is False

    def test_api_failure_is_unknown(self, svc, snap, conn):
        conn.instance_ha.segments.side_effect = RuntimeError("api down")
        assert svc.masakari_host_on_maintenance(snap) is None


class TestListenerResilience:
    def test_send_ignores_a_client_that_hung_up(self, svc):
        conn = MagicMock()
        conn.sendall.side_effect = BrokenPipeError(32, "Broken pipe")

        svc._send(conn, "reply")  # must not raise

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


class TestSocketPermissions:
    def test_listener_socket_is_owner_only(self, svc, tmp_path):
        sock = svc.create_listener_socket()
        try:
            mode = stat.S_IMODE(os.stat(svc.SOCKET_PATH).st_mode)
            assert mode == 0o600
        finally:
            sock.close()


class TestRecoveryCancellation:
    """A newer nic-down must cancel a recovery that has not finished."""

    @pytest.fixture
    def _actions(self, svc, monkeypatch):
        self.stop = MagicMock()
        self.shutdown = MagicMock()
        monkeypatch.setattr(svc, "stop_nova_compute", self.stop)
        monkeypatch.setattr(svc, "shutdown_vms", self.shutdown)

    def test_stale_generation_aborts_before_any_action(self, svc, monkeypatch):
        """A nic-down that arrived after the nic-up invalidates the recovery outright."""
        svc.save_state({"nova_compute_stopped": True, "recovery_requested": True})
        start = MagicMock()
        lookup = MagicMock()
        monkeypatch.setattr(svc, "start_nova_compute_with_retries", start)
        monkeypatch.setattr(svc, "host_in_maintenance", lookup)
        monkeypatch.setattr(svc, "Snap", MagicMock())

        stale = svc._outage_generation
        svc._cancel_pending_recovery()  # simulates the newer nic-down
        svc._recover_once(stale, svc.load_state())

        start.assert_not_called()
        lookup.assert_not_called()
        assert svc.load_state() is not None

    def test_nic_down_during_masakari_lookup_cancels_recovery(self, svc, monkeypatch, _actions):
        svc.save_state({"nova_compute_stopped": True, "recovery_requested": True})
        start = MagicMock()
        monkeypatch.setattr(svc, "start_nova_compute_with_retries", start)
        monkeypatch.setattr(svc, "Snap", MagicMock())
        entered = threading.Event()
        monkeypatch.setattr(
            svc,
            "masakari_host_on_maintenance",
            lambda snap: entered.set() or threading.Event().wait(5),
        )
        monkeypatch.setattr(svc, "MASAKARI_ATTEMPT_TIMEOUT", 0.05)
        monkeypatch.setattr(svc, "MAINTENANCE_LOOKUP_DELAY", 0.01)

        def nic_down():
            entered.wait(5)
            svc.handle_network_status(_message("nic-down"))

        canceller = threading.Thread(target=nic_down)
        canceller.start()
        svc._recover_once(0, svc.load_state())
        canceller.join(5)

        start.assert_not_called()
        assert svc.load_state() is not None
        assert self.stop.call_count == 1

    def test_nic_down_after_start_undoes_the_start(self, svc, monkeypatch, _actions):
        svc.save_state({"nova_compute_stopped": True, "recovery_requested": True})
        monkeypatch.setattr(svc, "host_in_maintenance", lambda snap, gen: False)
        monkeypatch.setattr(svc, "Snap", MagicMock())
        entered = threading.Event()

        def slow_start(gen):
            entered.set()
            threading.Event().wait(0.2)
            return True

        monkeypatch.setattr(svc, "start_nova_compute_with_retries", slow_start)

        def nic_down():
            entered.wait(5)
            threading.Event().wait(0.05)  # let the start return first
            svc.handle_network_status(_message("nic-down"))

        canceller = threading.Thread(target=nic_down)
        canceller.start()
        svc._recover_once(0, svc.load_state())
        canceller.join(5)

        # The recovery undid the start it had completed, in addition to the
        # stop the nic-down itself performed.
        assert self.stop.call_count == 2
        assert svc.load_state() is not None

    def test_nic_up_after_cancelled_recovery_recovers_normally(self, svc, monkeypatch):
        svc.save_state({"nova_compute_stopped": True, "recovery_requested": True})
        start = MagicMock(return_value=True)
        monkeypatch.setattr(svc, "start_nova_compute_with_retries", start)
        monkeypatch.setattr(svc, "host_in_maintenance", lambda snap, gen: False)
        monkeypatch.setattr(svc, "Snap", MagicMock())
        monkeypatch.setattr(svc.threading, "Thread", InlineThread)

        svc._cancel_pending_recovery()  # simulates the cancelled recovery
        svc.handle_network_status(_message("nic-up"))  # spawns a fresh worker
        _join_recovery_thread(svc)

        start.assert_called_once()
        assert svc.load_state() is None
