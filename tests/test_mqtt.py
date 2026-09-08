import json
from unittest.mock import MagicMock, patch, call

import pytest

from landbook_api import LandbookMQTTClient, DEFAULT_REGION, REGIONS


@pytest.fixture
def client():
    return LandbookMQTTClient(uid="u1", bearer_token="Bearer tok")


class TestConstruction:
    def test_defaults_to_us_mqtt_host(self, client):
        assert client._mqtt_host == REGIONS[DEFAULT_REGION]["mqtt_host"]

    def test_custom_mqtt_host(self):
        c = LandbookMQTTClient(uid="u1", bearer_token="t", mqtt_host="custom.host")
        assert c._mqtt_host == "custom.host"

    def test_initial_state(self, client):
        assert client._connected is False
        assert client._shutting_down is False
        assert client._client is None
        assert client._listeners == {}


class TestUpdateToken:
    def test_stores_new_token(self, client):
        client.update_token("Bearer new")
        assert client._bearer_token == "Bearer new"


class TestHaltReconnects:
    def test_sets_reauth_pending(self, client):
        client.halt_reconnects()
        assert client._reauth_pending is True

    def test_cancels_existing_timer(self, client):
        timer = MagicMock()
        client._reconnect_timer = timer
        client.halt_reconnects()
        timer.cancel.assert_called_once()
        assert client._reconnect_timer is None


class TestDisconnect:
    def test_disconnect_without_connect(self, client):
        client.disconnect()
        assert client._shutting_down is True
        assert client._connected is False

    def test_disconnect_stops_loop_and_disconnects(self, client):
        mock_mqtt = MagicMock()
        client._client = mock_mqtt
        client._connected = True
        client.disconnect()
        mock_mqtt.loop_stop.assert_called_once()
        mock_mqtt.disconnect.assert_called_once()
        assert client._client is None
        assert client._connected is False

    def test_disconnect_cancels_reconnect_timer(self, client):
        timer = MagicMock()
        client._reconnect_timer = timer
        client.disconnect()
        timer.cancel.assert_called_once()


class TestSubscribeDevice:
    def test_registers_callback(self, client):
        cb = MagicMock()
        client.subscribe_device("dev1", cb)
        assert cb in client._listeners["dev1"]

    def test_multiple_callbacks_same_device(self, client):
        cb1, cb2 = MagicMock(), MagicMock()
        client.subscribe_device("dev1", cb1)
        client.subscribe_device("dev1", cb2)
        assert len(client._listeners["dev1"]) == 2

    def test_subscribes_topics_when_connected(self, client):
        mock_mqtt = MagicMock()
        client._client = mock_mqtt
        client._connected = True
        client.subscribe_device("dev1", MagicMock())
        assert mock_mqtt.subscribe.call_count == 6
        topics = [c[0][0] for c in mock_mqtt.subscribe.call_args_list]
        for suffix in ("ack_", "bus_", "onl_", "ota_", "inf_", "loc_"):
            assert f"q/2/d/dev1/{suffix}" in topics

    def test_does_not_subscribe_when_not_connected(self, client):
        mock_mqtt = MagicMock()
        client._client = mock_mqtt
        client._connected = False
        client.subscribe_device("dev1", MagicMock())
        mock_mqtt.subscribe.assert_not_called()


class TestSendRead:
    def test_publishes_read_attr(self, client):
        mock_mqtt = MagicMock()
        client._client = mock_mqtt
        client._connected = True
        client.send_read("dev1", "pk1", "dk1", ["switch", "brightness"])
        mock_mqtt.publish.assert_called_once()
        topic, payload_str = mock_mqtt.publish.call_args[0]
        assert topic == "q/1/d/dev1/sys_"
        payload = json.loads(payload_str)
        assert payload["type"] == "READ-ATTR"
        assert payload["productKey"] == "pk1"
        assert payload["deviceKey"] == "dk1"
        assert json.loads(payload["kv"]) == ["switch", "brightness"]

    def test_noop_when_not_connected(self, client):
        client.send_read("dev1", "pk1", "dk1", ["switch"])

    def test_increments_msg_counter(self, client):
        mock_mqtt = MagicMock()
        client._client = mock_mqtt
        client._connected = True
        client.send_read("dev1", "pk1", "dk1", ["a"])
        client.send_read("dev1", "pk1", "dk1", ["b"])
        p1 = json.loads(mock_mqtt.publish.call_args_list[0][0][1])
        p2 = json.loads(mock_mqtt.publish.call_args_list[1][0][1])
        assert p2["msgId"] == p1["msgId"] + 1


class TestSendWrite:
    def test_publishes_write_attr(self, client):
        mock_mqtt = MagicMock()
        client._client = mock_mqtt
        client._connected = True
        client.send_write("dev1", "pk1", "dk1", {"switch": True})
        topic, payload_str = mock_mqtt.publish.call_args[0]
        assert topic == "q/1/d/dev1/sys_"
        payload = json.loads(payload_str)
        assert payload["type"] == "WRITE-ATTR"
        assert json.loads(payload["kv"]) == [{"switch": True}]

    def test_raises_when_not_connected(self, client):
        with pytest.raises(ConnectionError):
            client.send_write("dev1", "pk1", "dk1", {"switch": True})


class TestOnMessage:
    def test_dispatches_to_listeners(self, client):
        cb = MagicMock()
        client._listeners["dev1"] = [cb]
        msg = MagicMock()
        msg.topic = "q/2/d/dev1/bus_"
        msg.payload = json.dumps({"kv": {"switch": True}}).encode()
        client._on_message(None, None, msg)
        cb.assert_called_once_with("bus_", {"kv": {"switch": True}})

    def test_ignores_unknown_device(self, client):
        msg = MagicMock()
        msg.topic = "q/2/d/unknown/bus_"
        msg.payload = json.dumps({}).encode()
        client._on_message(None, None, msg)

    def test_ignores_short_topic(self, client):
        msg = MagicMock()
        msg.topic = "q/2/d"
        msg.payload = b"{}"
        client._on_message(None, None, msg)

    def test_ignores_non_json_payload(self, client):
        cb = MagicMock()
        client._listeners["dev1"] = [cb]
        msg = MagicMock()
        msg.topic = "q/2/d/dev1/bus_"
        msg.payload = b"not json"
        client._on_message(None, None, msg)
        cb.assert_not_called()

    def test_listener_exception_does_not_break_others(self, client):
        cb1 = MagicMock(side_effect=ValueError("boom"))
        cb2 = MagicMock()
        client._listeners["dev1"] = [cb1, cb2]
        msg = MagicMock()
        msg.topic = "q/2/d/dev1/ack_"
        msg.payload = json.dumps({"ok": True}).encode()
        client._on_message(None, None, msg)
        cb2.assert_called_once()


class TestOnConnect:
    def test_successful_connect_sets_connected(self, client):
        client._listeners["dev1"] = [MagicMock()]
        mock_mqtt = MagicMock()
        client._client = mock_mqtt
        client._on_connect(None, None, None, 0, None)
        assert client._connected is True
        assert mock_mqtt.subscribe.call_count == 6

    def test_on_reconnect_callback_fired(self, client):
        cb = MagicMock()
        client._on_reconnect = cb
        client._client = MagicMock()
        client._on_connect(None, None, None, "Success", None)
        cb.assert_called_once()

    def test_failed_connect_stays_disconnected(self, client):
        client._on_connect(None, None, None, 5, None)
        assert client._connected is False


class TestOnDisconnect:
    def test_clean_shutdown_no_reconnect(self, client):
        client._shutting_down = True
        client._on_disconnect(None, None, None, 0, None)
        assert client._connected is False
        assert client._reconnect_timer is None

    def test_reauth_pending_no_reconnect(self, client):
        client._connected = True
        client._reauth_pending = True
        client._on_disconnect(None, None, None, 0, None)
        assert client._connected is False
        assert client._reconnect_timer is None

    @patch.object(LandbookMQTTClient, "_schedule_reconnect")
    def test_unexpected_disconnect_schedules_reconnect(self, mock_sched, client):
        client._connected = True
        client._on_disconnect(None, None, None, 1, None)
        assert client._connected is False
        mock_sched.assert_called_once_with(delay=5)


class TestMsgCounterWraps:
    def test_wraps_at_0xFFFF(self, client):
        mock_mqtt = MagicMock()
        client._client = mock_mqtt
        client._connected = True
        client._msg_counter = 0xFFFE
        client.send_read("d", "p", "k", ["x"])
        client.send_read("d", "p", "k", ["x"])
        p1 = json.loads(mock_mqtt.publish.call_args_list[0][0][1])
        p2 = json.loads(mock_mqtt.publish.call_args_list[1][0][1])
        assert p1["msgId"] == 0xFFFF
        assert p2["msgId"] == 0
