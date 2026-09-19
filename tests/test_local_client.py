import base64
import threading
import time

import pytest

from landbook_api.local_client import (
    CMD_STATUS_PUSH_OBSERVED,
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
