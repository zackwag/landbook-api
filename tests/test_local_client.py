import base64
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from landbook_api.local_client import (
    CMD_HEARTBEAT_PING,
    CMD_HEARTBEAT_REPLY,
    CMD_HEARTBEAT_START,
    CMD_STATUS_PUSH_OBSERVED,
    CMD_WRITE_ACK,
    DATA_STALL_TIMEOUT,
    HEARTBEAT_PONG_TIMEOUT,
    LandbookLocalClient,
    _parse_discovery_reply,
)
from landbook_api.local_protocol import (
    TYPE_BOOL_TRUE,
    TYPE_BYTES,
    TYPE_NUMBER,
    DecodedFrame,
    TTLVField,
    encode_fields,
)

AUTH_KEY_B64 = base64.b64encode(b"0123456789abcdef").decode()


@pytest.fixture
def client():
    return LandbookLocalClient(
        product_key="p11vkW",
        device_key="A8DD9FE36D91",
        auth_key_b64=AUTH_KEY_B64,
        ip="192.168.1.50",
        port=6607,
    )


def make_discovery_frame(
    pk="p11vkW", dk="A8DD9FE36D91", ip="192.168.1.50", port=6607, version=1
) -> DecodedFrame:
    fields = [
        TTLVField(3, TYPE_BYTES, pk.encode()),
        TTLVField(4, TYPE_BYTES, dk.encode()),
        TTLVField(5, TYPE_BYTES, ip.encode()),
        TTLVField(6, TYPE_NUMBER, port),
        TTLVField(7, TYPE_NUMBER, version),
    ]
    return DecodedFrame(packet_id=1, cmd=28721, payload=encode_fields(fields))


class TestParseDiscoveryReply:
    def test_valid_reply(self):
        device = _parse_discovery_reply(make_discovery_frame())
        assert device is not None
        assert device.product_key == "p11vkW"
        assert device.device_key == "A8DD9FE36D91"
        assert device.ip == "192.168.1.50"
        assert device.port == 6607
        assert device.version == 1

    def test_wrong_cmd_ignored(self):
        frame = DecodedFrame(packet_id=1, cmd=1, payload=b"")
        assert _parse_discovery_reply(frame) is None

    def test_missing_required_field_ignored(self):
        # no port (id=6) -> incomplete, should be rejected
        fields = [TTLVField(3, TYPE_BYTES, b"pk"), TTLVField(4, TYPE_BYTES, b"dk")]
        frame = DecodedFrame(packet_id=1, cmd=28721, payload=encode_fields(fields))
        assert _parse_discovery_reply(frame) is None

    def test_malformed_payload_ignored(self):
        frame = DecodedFrame(packet_id=1, cmd=28721, payload=b"\xff\xff\xff")
        assert _parse_discovery_reply(frame) is None


class TestPropertyCache:
    def test_on_data_updates_properties_and_fires_callback(self, client):
        received = []
        client.on_update = lambda fields: received.append(fields)

        payload = encode_fields([TTLVField(1, TYPE_BOOL_TRUE, True)])
        client._on_data(payload)

        assert client.properties == {1: True}
        assert received == [[TTLVField(1, TYPE_BOOL_TRUE, True)]]

    def test_write_ack_does_not_touch_property_cache(self, client):
        client.properties[1] = True  # simulate a known-good prior state
        acks = []
        client.on_write_ack = lambda fields: acks.append(fields)

        # A write ack whose payload happens to reuse id=1 with an unrelated
        # value must not clobber the real property cache for id=1.
        ack_payload = encode_fields([TTLVField(1, TYPE_NUMBER, 0)])
        client._on_write_ack(ack_payload)

        assert client.properties == {1: True}
        assert acks == [[TTLVField(1, TYPE_NUMBER, 0)]]

    def test_malformed_data_frame_logged_not_raised(self, client, caplog):
        client._on_data(b"\xff\xff\xff")  # not valid TTLV
        assert client.properties == {}

    def test_decrypt_failure_logged_not_raised(self, client):
        client._cipher_key = b"0123456789abcdef"
        client._cipher_iv = b"0123456789abcdef"
        client._on_data(b"not a valid ciphertext block!!!!")
        assert client.properties == {}


class TestReadAndWait:
    def test_returns_immediately_when_already_cached(self, client):
        client.properties[1] = True
        client.properties[2] = 5
        client._send = lambda *a, **kw: None  # avoid touching a real socket
        result = client.read_and_wait([1, 2], timeout=1.0)
        assert result == {1: True, 2: 5}

    def test_waits_for_a_background_update(self, client):
        client._send = lambda *a, **kw: None

        def deliver_later():
            time.sleep(0.05)
            client._on_data(encode_fields([TTLVField(9, TYPE_NUMBER, 42)]))

        threading.Thread(target=deliver_later, daemon=True).start()
        result = client.read_and_wait([9], timeout=2.0)
        assert result == {9: 42}

    def test_partial_result_on_timeout(self, client):
        client._send = lambda *a, **kw: None
        client.properties[1] = True  # only one of the two requested ids ever arrives
        result = client.read_and_wait([1, 2], timeout=0.1)
        assert result == {1: True}

    def test_empty_result_on_timeout_when_nothing_arrives(self, client):
        client._send = lambda *a, **kw: None
        result = client.read_and_wait([99], timeout=0.1)
        assert result == {}


class TestStatusPushCmdRecognized:
    def test_status_push_observed_constant_matches_real_device_finding(self):
        # cmd=20, observed as a continuous unsolicited push on a real
        # GE OmniBreeze fan (p11vkW) — see local_client's module docstring.
        assert CMD_STATUS_PUSH_OBSERVED == 20


class TestDisconnectDetection:
    def test_on_disconnect_fires_on_broken_socket(self, client):
        fired = []
        client.on_disconnect = lambda: fired.append(True)
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = OSError("connection reset")
        client._sock = mock_sock

        client._recv_loop()

        assert fired == [True]

    def test_on_disconnect_fires_when_remote_closes_cleanly(self, client):
        fired = []
        client.on_disconnect = lambda: fired.append(True)
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""  # empty read = remote closed
        client._sock = mock_sock

        client._recv_loop()

        assert fired == [True]

    def test_on_disconnect_not_fired_for_caller_initiated_disconnect(self, client):
        """disconnect() sets _shutting_down before touching the socket —
        _recv_loop must recognize that as a clean, expected exit and not
        report it as a surprise disconnection."""
        fired = []
        client.on_disconnect = lambda: fired.append(True)
        client._shutting_down = True
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = OSError("bad file descriptor")
        client._sock = mock_sock

        client._recv_loop()

        assert fired == []

    def test_missing_on_disconnect_callback_does_not_raise(self, client):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = OSError("connection reset")
        client._sock = mock_sock

        client._recv_loop()  # must not raise with on_disconnect left unset


class TestIsConnected:
    def test_false_before_connecting(self, client):
        assert client.is_connected is False

    def test_true_once_socket_open_and_logged_in(self, client):
        client._sock = MagicMock()
        client._logged_in.set()
        assert client.is_connected is True

    def test_false_while_logged_in_flag_not_yet_set(self, client):
        client._sock = MagicMock()
        assert client.is_connected is False

    def test_false_after_disconnect(self, client):
        client._sock = MagicMock()
        client._logged_in.set()
        client.disconnect()
        assert client.is_connected is False


class TestHeartbeatPongTimeout:
    def test_heartbeat_reply_updates_last_pong(self, client):
        client._last_pong = 100.0
        frame = DecodedFrame(packet_id=1, cmd=CMD_HEARTBEAT_REPLY, payload=b"")
        with patch("landbook_api.local_client.time") as mock_time:
            mock_time.monotonic.return_value = 200.0
            client._handle_frame(frame)
        assert client._last_pong == 200.0

    def test_heartbeat_constants(self):
        assert CMD_HEARTBEAT_START == 28729
        assert CMD_HEARTBEAT_PING == 28727
        assert CMD_HEARTBEAT_REPLY == 28728

    def test_pong_timeout_constant(self):
        assert HEARTBEAT_PONG_TIMEOUT == 30.0

    def test_send_heartbeat_sends_ping_cmd_with_empty_payload(self, client):
        client._sock = MagicMock()
        client._cipher_key = b"0123456789abcdef"
        client._cipher_iv = b"0123456789abcdef"
        sent = []
        client._send = lambda cmd, payload: sent.append((cmd, payload))
        with patch("landbook_api.local_client.time") as mock_time:
            mock_time.monotonic.return_value = 100.0
            client._last_pong = 90.0
            client._send_heartbeat()
        assert sent == [(CMD_HEARTBEAT_PING, b"")]
        assert client._heartbeat_timer is not None
        client._heartbeat_timer.cancel()

    def test_send_heartbeat_tears_down_on_stale_pong(self, client):
        client._sock = MagicMock()
        client._logged_in.set()
        client._last_pong = 50.0
        force_called = []
        client._force_disconnect = lambda: force_called.append(True)
        with patch("landbook_api.local_client.time") as mock_time:
            mock_time.monotonic.return_value = 100.0
            client._send_heartbeat()
        assert force_called == [True]

    def test_force_disconnect_closes_socket_and_cancels_timer(self, client):
        mock_sock = MagicMock()
        client._sock = mock_sock
        mock_timer = MagicMock()
        client._heartbeat_timer = mock_timer
        client._force_disconnect()
        mock_timer.cancel.assert_called_once()
        mock_sock.close.assert_called_once()
        assert client._heartbeat_timer is None

    def test_force_disconnect_triggers_on_disconnect_via_recv_loop(self, client):
        fired = []
        client.on_disconnect = lambda: fired.append(True)
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = OSError("bad file descriptor")
        client._sock = mock_sock
        client._recv_loop()
        assert fired == [True]

    def test_last_pong_initialized_on_login(self, client):
        assert client._last_pong == 0.0
        assert client.last_property_update == 0.0
        client._sock = MagicMock()
        sent = []
        client._send = lambda cmd, payload: sent.append((cmd, payload))
        client._random_challenge = "abcdefghijklmnop"
        with patch("landbook_api.local_client.time") as mock_time:
            mock_time.monotonic.return_value = 999.0
            login_payload = encode_fields([TTLVField(3, TYPE_NUMBER, 0)])
            client._on_login_result(login_payload)
        assert client._last_pong == 999.0
        assert client.last_property_update == 999.0
        assert sent[0][0] == CMD_HEARTBEAT_START
        assert sent[0][1] != b""
        if client._heartbeat_timer:
            client._heartbeat_timer.cancel()


class TestDataStallTimeout:
    def test_data_stall_constant(self):
        assert DATA_STALL_TIMEOUT == 90.0

    def test_on_data_updates_last_property_update(self, client):
        client.last_property_update = 100.0
        payload = encode_fields([TTLVField(1, TYPE_BOOL_TRUE, True)])
        with patch("landbook_api.local_client.time") as mock_time:
            mock_time.monotonic.return_value = 200.0
            client._on_data(payload)
        assert client.last_property_update == 200.0

    def test_send_heartbeat_tears_down_on_data_stall(self, client):
        client._sock = MagicMock()
        client._last_pong = 90.0
        client.last_property_update = 5.0
        force_called = []
        client._force_disconnect = lambda: force_called.append(True)
        with patch("landbook_api.local_client.time") as mock_time:
            mock_time.monotonic.return_value = 100.0
            client._send_heartbeat()
        assert force_called == [True]

    def test_send_heartbeat_ok_when_data_recent(self, client):
        client._sock = MagicMock()
        sent = []
        client._send = lambda cmd, payload: sent.append(cmd)
        with patch("landbook_api.local_client.time") as mock_time:
            mock_time.monotonic.return_value = 100.0
            client._last_pong = 90.0
            client.last_property_update = 90.0
            client._send_heartbeat()
        assert len(sent) == 1
        assert client._heartbeat_timer is not None
        client._heartbeat_timer.cancel()

    def test_pong_timeout_checked_before_data_stall(self, client):
        """If both pong and data are stale, pong timeout fires first
        (it's checked first in _send_heartbeat)."""
        client._sock = MagicMock()
        client._last_pong = 5.0
        client.last_property_update = 5.0
        force_called = []
        client._force_disconnect = lambda: force_called.append(True)
        with patch("landbook_api.local_client.time") as mock_time:
            mock_time.monotonic.return_value = 100.0
            client._send_heartbeat()
        assert force_called == [True]

    def test_data_stall_with_fresh_pong(self, client):
        """The key scenario: heartbeats answering fine but no property
        pushes — data stall should fire even though pong is fresh."""
        client._sock = MagicMock()
        client._last_pong = 99.0
        client.last_property_update = 5.0
        force_called = []
        client._force_disconnect = lambda: force_called.append(True)
        with patch("landbook_api.local_client.time") as mock_time:
            mock_time.monotonic.return_value = 100.0
            client._send_heartbeat()
        assert force_called == [True]


class TestWriteAndWait:
    def test_returns_true_when_ack_arrives(self, client):
        client._sock = MagicMock()
        client._cipher_key = b"0123456789abcdef"
        client._cipher_iv = b"0123456789abcdef"

        def _send_with_ack(cmd, payload):
            if cmd == 19:  # CMD_WRITE
                ack_payload = encode_fields([TTLVField(1, TYPE_NUMBER, 0)])
                threading.Timer(
                    0.01, client._on_write_ack, args=[client._encrypt(ack_payload)]
                ).start()

        client._send = _send_with_ack
        fields = [TTLVField(1, TYPE_BOOL_TRUE, True)]
        assert client.write_and_wait(fields, timeout=1.0) is True

    def test_returns_false_on_timeout(self, client):
        client._sock = MagicMock()
        client._cipher_key = b"0123456789abcdef"
        client._cipher_iv = b"0123456789abcdef"
        client._send = lambda cmd, payload: None

        fields = [TTLVField(1, TYPE_BOOL_TRUE, True)]
        assert client.write_and_wait(fields, timeout=0.05) is False

    def test_clears_event_after_completion(self, client):
        client._sock = MagicMock()
        client._cipher_key = b"0123456789abcdef"
        client._cipher_iv = b"0123456789abcdef"
        client._send = lambda cmd, payload: None

        fields = [TTLVField(1, TYPE_BOOL_TRUE, True)]
        client.write_and_wait(fields, timeout=0.05)
        assert client._write_ack_event is None

    def test_on_write_ack_callback_still_fires(self, client):
        client._sock = MagicMock()
        client._cipher_key = b"0123456789abcdef"
        client._cipher_iv = b"0123456789abcdef"

        acks = []
        client.on_write_ack = lambda fields: acks.append(fields)

        def _send_with_ack(cmd, payload):
            if cmd == 19:
                ack_payload = encode_fields([TTLVField(1, TYPE_NUMBER, 0)])
                threading.Timer(
                    0.01, client._on_write_ack, args=[client._encrypt(ack_payload)]
                ).start()

        client._send = _send_with_ack
        fields = [TTLVField(1, TYPE_BOOL_TRUE, True)]
        client.write_and_wait(fields, timeout=1.0)
        assert len(acks) == 1

    def test_write_ack_cmd_constant(self):
        assert CMD_WRITE_ACK == 28726
