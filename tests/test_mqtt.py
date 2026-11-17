import json
import threading
from unittest.mock import MagicMock

import pytest
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.reasoncodes import ReasonCode

from landbook_api import DEFAULT_REGION, REGIONS, LandbookMQTTClient
from landbook_api import mqtt_client as mqtt_module

ACCEPTED = ReasonCode(PacketTypes.CONNACK, "Success")
NOT_AUTHORIZED = ReasonCode(PacketTypes.CONNACK, "Not authorized")
DROPPED = ReasonCode(PacketTypes.DISCONNECT, "Unspecified error")
SUFFIXES = ("ack_", "bus_", "onl_", "ota_", "inf_", "loc_")


class FakeTimer:
    def __init__(self, interval, function):
        self.interval = interval
        self.function = function
        self.cancelled = False
        self.daemon = False

    def start(self):
        pass

    def cancel(self):
        self.cancelled = True

    def fire(self):
        self.function()


class Broker:
    """Stands in for paho: every mqtt.Client() the library creates is a mock
    whose connect() answers with `connack` (None = never answers)."""

    def __init__(self, monkeypatch):
        self.clients: list[MagicMock] = []
        self.timers: list[FakeTimer] = []
        self.connack: ReasonCode | None = ACCEPTED
        self.connect_error: Exception | None = None
        self.on_disconnect_during_teardown = False
        monkeypatch.setattr(mqtt_module.mqtt, "Client", self._new_client)
        monkeypatch.setattr(mqtt_module.threading, "Timer", self._new_timer)

    def _new_client(self, *args, **kwargs):
        client = MagicMock()
        client.constructed_with = kwargs

        def connect(*_a, **_kw):
            if self.connect_error:
                raise self.connect_error
            if self.connack is not None:
                client.on_connect(client, None, None, self.connack, None)

        def disconnect():
            if self.on_disconnect_during_teardown:
                client.on_disconnect(client, None, None, DROPPED, None)

        client.connect.side_effect = connect
        client.disconnect.side_effect = disconnect
        self.clients.append(client)
        return client

    def _new_timer(self, interval, function):
        timer = FakeTimer(interval, function)
        self.timers.append(timer)
        return timer

    @property
    def current(self) -> MagicMock:
        return self.clients[-1]

    def drop(self, client=None):
        client = client or self.current
        client.on_disconnect(client, None, None, DROPPED, None)

    def deliver(self, topic, payload, client=None):
        client = client or self.current
        msg = MagicMock()
        msg.topic = topic
        msg.payload = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        client.on_message(client, None, msg)

    def published(self, client=None):
        client = client or self.current
        return [(c.args[0], json.loads(c.args[1])) for c in client.publish.call_args_list]

    def subscribed(self, client=None):
        client = client or self.current
        return [c.args[0] for c in client.subscribe.call_args_list]

    def pending_timers(self):
        return [t for t in self.timers if not t.cancelled]


@pytest.fixture
def broker(monkeypatch):
    return Broker(monkeypatch)


@pytest.fixture
def client(broker):
    return LandbookMQTTClient(uid="u1", bearer_token="Bearer tok")


class TestConnect:
    def test_configures_websocket_tls_session(self, broker, client):
        client.connect()
        paho = broker.current
        paho.ws_set_options.assert_called_once_with(path="/ws/v2")
        paho.tls_set.assert_called_once()
        paho.username_pw_set.assert_called_once_with("", "Bearer tok")
        paho.connect.assert_called_once_with(
            REGIONS[DEFAULT_REGION]["mqtt_host"], 8443, keepalive=40
        )
        assert client.is_connected

    def test_custom_mqtt_host(self, broker):
        LandbookMQTTClient(uid="u1", bearer_token="t", mqtt_host="custom.host").connect()
        assert broker.current.connect.call_args.args[0] == "custom.host"

    def test_refused_connack_raises_and_cleans_up(self, broker, client):
        broker.connack = NOT_AUTHORIZED
        with pytest.raises(ConnectionError, match="refused"):
            client.connect()
        broker.current.loop_stop.assert_called_once()
        broker.current.disconnect.assert_called_once()
        assert not client.is_connected

    def test_no_connack_times_out_and_cleans_up(self, broker, client, monkeypatch):
        monkeypatch.setattr(mqtt_module, "CONNECT_TIMEOUT", 0.01)
        broker.connack = None
        with pytest.raises(ConnectionError, match="timed out"):
            client.connect()
        broker.current.loop_stop.assert_called_once()
        assert not client.is_connected

    def test_socket_error_propagates_and_cleans_up(self, broker, client):
        broker.connect_error = OSError("unreachable")
        with pytest.raises(OSError, match="unreachable"):
            client.connect()
        broker.current.loop_stop.assert_called_once()
        assert not client.is_connected

    def test_connect_again_replaces_the_old_session(self, broker, client):
        client.connect()
        first = broker.current
        client.connect()
        first.loop_stop.assert_called_once()
        first.disconnect.assert_called_once()
        assert len(broker.clients) == 2
        assert client.is_connected

    def test_on_connect_callback_fires(self, broker, client):
        client.on_connect = MagicMock()
        client.connect()
        client.on_connect.assert_called_once_with()

    def test_paho_does_not_retry_on_its_own(self, broker, client):
        # Only the library's reconnect (fresh client, refreshed token) may retry.
        client.connect()
        assert broker.current.constructed_with["reconnect_on_failure"] is False

    def test_teardown_does_not_hold_the_lock_paho_callbacks_need(self, broker, client):
        client.connect()
        old = broker.current

        def loop_stop():
            # paho joins its network thread here; that thread may be mid-callback.
            t = threading.Thread(target=old.on_connect, args=(old, None, None, ACCEPTED, None))
            t.start()
            t.join(2.0)
            assert not t.is_alive()

        old.loop_stop.side_effect = loop_stop
        client.reconnect()
        assert client.is_connected


class TestLandbookHaCompatibility:
    """landbook-ha <= 2.2.6 touches these private names directly."""

    def test_on_reconnect_assignment(self, broker, client):
        cb = MagicMock()
        client._on_reconnect = cb
        client.connect()
        cb.assert_called_once_with()

    def test_connected_reads_as_bool(self, broker, client):
        client.connect()
        assert client._connected is True
        broker.drop()
        assert client._connected is False

    def test_clearing_reauth_pending_resumes_auto_reconnect(self, broker, client):
        client.connect()
        client.halt_reconnects()
        assert client._reauth_pending is True
        client._reauth_pending = False
        broker.drop()
        assert len(broker.pending_timers()) == 1


class TestSubscriptions:
    def test_subscribing_before_connect_subscribes_on_connect(self, broker, client):
        client.subscribe_device("dev1", MagicMock())
        client.connect()
        assert sorted(broker.subscribed()) == sorted(f"q/2/d/dev1/{s}" for s in SUFFIXES)

    def test_subscribing_while_connected_subscribes_once_per_device(self, broker, client):
        client.connect()
        client.subscribe_device("dev1", MagicMock())
        client.subscribe_device("dev1", MagicMock())
        assert len(broker.subscribed()) == len(SUFFIXES)

    def test_new_session_resubscribes(self, broker, client):
        client.subscribe_device("dev1", MagicMock())
        client.connect()
        client.reconnect()
        assert len(broker.subscribed()) == len(SUFFIXES)

    def test_dispatches_message_to_device_callbacks(self, broker, client):
        cb1, cb2, other = MagicMock(), MagicMock(), MagicMock()
        client.subscribe_device("dev1", cb1)
        client.subscribe_device("dev1", cb2)
        client.subscribe_device("dev2", other)
        client.connect()
        broker.deliver("q/2/d/dev1/bus_", {"kv": {"switch": True}})
        cb1.assert_called_once_with("bus_", {"kv": {"switch": True}})
        cb2.assert_called_once_with("bus_", {"kv": {"switch": True}})
        other.assert_not_called()

    @pytest.mark.parametrize(
        ("topic", "payload"), [("q/2/d", b"{}"), ("q/2/d/dev1/bus_", b"not json")]
    )
    def test_ignores_unparseable_messages(self, broker, client, topic, payload):
        cb = MagicMock()
        client.subscribe_device("dev1", cb)
        client.connect()
        broker.deliver(topic, payload)
        cb.assert_not_called()

    def test_listener_exception_does_not_break_others(self, broker, client):
        cb2 = MagicMock()
        client.subscribe_device("dev1", MagicMock(side_effect=ValueError("boom")))
        client.subscribe_device("dev1", cb2)
        client.connect()
        broker.deliver("q/2/d/dev1/ack_", {"ok": True})
        cb2.assert_called_once()

    def test_callback_unsubscribing_itself_does_not_skip_the_next(self, broker, client):
        after = MagicMock()

        def once(_suffix, _payload):
            client.unsubscribe_device("dev1", once)

        client.subscribe_device("dev1", once)
        client.subscribe_device("dev1", after)
        client.connect()
        broker.deliver("q/2/d/dev1/bus_", {})
        after.assert_called_once()

    def test_unsubscribe_removes_only_that_callback(self, broker, client):
        cb1, cb2 = MagicMock(), MagicMock()
        client.subscribe_device("dev1", cb1)
        client.subscribe_device("dev1", cb2)
        client.unsubscribe_device("dev1", cb1)
        client.unsubscribe_device("dev1", MagicMock())
        client.unsubscribe_device("nonexistent", MagicMock())
        client.connect()
        broker.deliver("q/2/d/dev1/bus_", {})
        cb1.assert_not_called()
        cb2.assert_called_once()


class TestPublish:
    def test_send_read(self, broker, client):
        client.connect()
        client.send_read("dev1", "pk1", "dk1", ["switch", "brightness"])
        [(topic, payload)] = broker.published()
        assert topic == "q/1/d/dev1/sys_"
        assert payload["type"] == "READ-ATTR"
        assert payload["productKey"] == "pk1"
        assert payload["deviceKey"] == "dk1"
        assert json.loads(payload["kv"]) == ["switch", "brightness"]

    def test_send_write(self, broker, client):
        client.connect()
        client.send_write("dev1", "pk1", "dk1", {"switch": True})
        [(topic, payload)] = broker.published()
        assert topic == "q/1/d/dev1/sys_"
        assert payload["type"] == "WRITE-ATTR"
        assert json.loads(payload["kv"]) == [{"switch": True}]

    def test_msg_ids_increment_and_wrap_at_16_bits(self, broker, monkeypatch):
        monkeypatch.setattr(mqtt_module.time, "time", lambda: 65.5345)  # seeds 0xFFFE
        client = LandbookMQTTClient(uid="u1", bearer_token="t")
        client.connect()
        for _ in range(3):
            client.send_read("d", "p", "k", ["x"])
        assert [p["msgId"] for _, p in broker.published()] == [0xFFFF, 0, 1]

    def test_read_while_disconnected_is_dropped_not_replayed(self, broker, client):
        client.send_read("dev1", "pk1", "dk1", ["switch"])
        client.connect()
        assert broker.published() == []


class TestDeferredWrites:
    def test_writes_while_disconnected_replay_in_order_before_on_connect(self, broker, client):
        client.send_write("dev1", "pk", "dk1", {"switch": True})
        client.send_write("dev1", "pk", "dk1", {"speed": 5})
        published_at_on_connect = []
        client.on_connect = lambda: published_at_on_connect.extend(broker.published())

        client.connect()

        kvs = [json.loads(p["kv"]) for _, p in published_at_on_connect]
        assert kvs == [[{"switch": True}], [{"speed": 5}]]

    def test_replayed_only_once(self, broker, client):
        client.send_write("dev1", "pk", "dk1", {"switch": True})
        client.connect()
        client.reconnect()
        assert broker.published() == []

    def test_write_during_a_drop_replays_after_auto_reconnect(self, broker, client):
        client.connect()
        broker.drop()
        client.send_write("dev1", "pk", "dk1", {"switch": True})
        broker.pending_timers()[0].fire()
        [(_, payload)] = broker.published()
        assert json.loads(payload["kv"]) == [{"switch": True}]

    def test_expired_writes_are_dropped(self, broker, client, monkeypatch):
        monkeypatch.setattr(mqtt_module, "WRITE_RETRY_WINDOW", -1.0)
        client.send_write("dev1", "pk", "dk1", {"switch": True})
        client.connect()
        assert broker.published() == []


class TestAutoReconnect:
    def test_unexpected_drop_reconnects_with_refreshed_token(self, broker):
        client = LandbookMQTTClient(
            uid="u1", bearer_token="Bearer old", token_refresher=lambda: "Bearer new"
        )
        client.on_connect = MagicMock()
        client.connect()
        broker.drop()
        assert not client.is_connected

        [timer] = broker.pending_timers()
        assert timer.interval == mqtt_module.RECONNECT_DELAY
        timer.fire()

        assert len(broker.clients) == 2
        broker.current.username_pw_set.assert_called_once_with("", "Bearer new")
        assert client.is_connected
        assert client.on_connect.call_count == 2

    def test_failed_token_refresh_reconnects_with_old_token(self, broker):
        def refresher():
            raise RuntimeError("refresh down")

        client = LandbookMQTTClient(uid="u1", bearer_token="Bearer old", token_refresher=refresher)
        client.connect()
        broker.drop()
        broker.pending_timers()[0].fire()
        broker.current.username_pw_set.assert_called_once_with("", "Bearer old")
        assert client.is_connected

    def test_refresher_that_halts_reconnects_stops_the_attempt(self, broker):
        client = None

        def refresher():
            client.halt_reconnects()
            return "Bearer new"

        client = LandbookMQTTClient(uid="u1", bearer_token="t", token_refresher=refresher)
        client.connect()
        broker.drop()
        broker.pending_timers()[0].fire()
        assert len(broker.clients) == 1

    def test_failed_reconnect_retries_later(self, broker, client):
        client.connect()
        broker.drop()
        broker.connack = NOT_AUTHORIZED
        broker.pending_timers()[0].fire()
        [retry] = broker.pending_timers()
        assert retry.interval == mqtt_module.RECONNECT_RETRY_DELAY

        broker.connack = ACCEPTED
        retry.fire()
        assert client.is_connected

    def test_halt_reconnects_cancels_pending_and_future_attempts(self, broker, client):
        client.connect()
        broker.drop()
        client.halt_reconnects()
        assert broker.pending_timers() == []
        client.connect()
        client.halt_reconnects()
        broker.drop()
        assert broker.pending_timers() == []

    def test_explicit_connect_resumes_auto_reconnect_after_halt(self, broker, client):
        client.connect()
        client.halt_reconnects()
        client.connect()
        broker.drop()
        assert len(broker.pending_timers()) == 1

    def test_timer_firing_after_an_explicit_reconnect_leaves_it_alone(self, broker, client):
        client.connect()
        broker.drop()
        timer = broker.pending_timers()[0]
        client.reconnect()  # e.g. a watchdog got there first
        timer.fire()  # a timer that was already running when reconnect() hit
        assert len(broker.clients) == 2
        assert client.is_connected

    def test_disconnect_does_not_reconnect(self, broker, client):
        broker.on_disconnect_during_teardown = True
        client.connect()
        broker.drop()
        timer = broker.timers[-1]
        client.disconnect()
        assert broker.pending_timers() == []
        timer.fire()  # a timer that was already running when disconnect() hit
        assert len(broker.clients) == 1
        assert not client.is_connected


class TestReconnect:
    def test_old_sessions_disconnect_does_not_schedule_duplicate_reconnect(self, broker, client):
        """Regression for landbook-ha#27: tearing down the old client fires its
        on_disconnect (synchronously here; paho may also do it later from its
        network thread). That must not schedule a reconnect on top of the
        one reconnect() performs — a second live session for the same
        account gets every command rejected."""
        broker.on_disconnect_during_teardown = True
        client.connect()
        old = broker.current
        client.reconnect()
        broker.drop(old)  # a late callback from the old network thread
        assert broker.pending_timers() == []
        assert client.is_connected
        assert len(broker.clients) == 2

    def test_old_sessions_late_connack_is_ignored(self, broker, client):
        client.subscribe_device("dev1", MagicMock())
        client.on_connect = MagicMock()
        client.connect()
        old = broker.current
        client.reconnect()
        old.on_connect(old, None, None, ACCEPTED, None)
        assert broker.subscribed() == [f"q/2/d/dev1/{s}" for s in SUFFIXES]
        assert client.on_connect.call_count == 2

    def test_failure_propagates_and_later_drops_still_auto_reconnect(self, broker, client):
        client.connect()
        broker.connack = NOT_AUTHORIZED
        with pytest.raises(ConnectionError):
            client.reconnect()
        broker.connack = ACCEPTED
        client.reconnect()
        broker.drop()
        assert len(broker.pending_timers()) == 1


class TestUpdateToken:
    def test_next_connection_uses_new_token(self, broker, client):
        client.update_token("Bearer new")
        client.connect()
        broker.current.username_pw_set.assert_called_once_with("", "Bearer new")
