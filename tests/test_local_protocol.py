import struct

import pytest

from landbook_api.local_protocol import (
    SYNC,
    TYPE_BOOL_FALSE,
    TYPE_BOOL_TRUE,
    TYPE_BYTES,
    TYPE_NUMBER,
    TYPE_RAW_HEX,
    TYPE_STRUCT,
    FrameDecoder,
    ProtocolError,
    TTLVField,
    decode_fields,
    encode_field,
    encode_fields,
    encode_frame,
    encode_id_list,
    field_for_property,
)


class TestNumberRoundTrip:
    @pytest.mark.parametrize(
        "value",
        [0, 1, -1, 30, 255, 256, 65535, 2**32, -(2**40), 1234567890123],
    )
    def test_integers(self, value):
        encoded = encode_fields([TTLVField(1, TYPE_NUMBER, value)])
        decoded = decode_fields(encoded)
        assert decoded == [TTLVField(1, TYPE_NUMBER, value)]

    @pytest.mark.parametrize("value", [0.5, -0.5, 1.25, 3.0, 99.99, -12.125])
    def test_floats(self, value):
        encoded = encode_fields([TTLVField(2, TYPE_NUMBER, value)])
        decoded = decode_fields(encoded)
        assert len(decoded) == 1
        assert decoded[0].id == 2
        assert decoded[0].type == TYPE_NUMBER
        assert decoded[0].value == pytest.approx(value)

    def test_zero_encodes_to_known_bytes(self):
        # header (id=1, type=2) = (1<<3)|2 = 0x0A; marker byte 0x00; value byte 0x00
        assert encode_field(TTLVField(1, TYPE_NUMBER, 0)) == b"\x00\x0a\x00\x00"

    def test_thirty_encodes_to_known_bytes(self):
        # matches the app's heartbeat field TTLVData(1, 2, 30L)
        assert encode_field(TTLVField(1, TYPE_NUMBER, 30)) == b"\x00\x0a\x00\x1e"


class TestBoolRoundTrip:
    def test_true(self):
        encoded = encode_fields([TTLVField(5, TYPE_BOOL_TRUE, None)])
        assert encoded == struct.pack(">H", (5 << 3) | TYPE_BOOL_TRUE)
        assert decode_fields(encoded) == [TTLVField(5, TYPE_BOOL_TRUE, True)]

    def test_false(self):
        encoded = encode_fields([TTLVField(5, TYPE_BOOL_FALSE, None)])
        assert encoded == struct.pack(">H", (5 << 3) | TYPE_BOOL_FALSE)
        assert decode_fields(encoded) == [TTLVField(5, TYPE_BOOL_FALSE, False)]


class TestBytesRoundTrip:
    def test_string_value(self):
        encoded = encode_fields([TTLVField(1, TYPE_BYTES, b"hello")])
        decoded = decode_fields(encoded)
        assert decoded == [TTLVField(1, TYPE_BYTES, b"hello")]

    def test_str_input_encoded_as_utf8(self):
        encoded = encode_fields([TTLVField(1, TYPE_BYTES, "abc123")])
        decoded = decode_fields(encoded)
        assert decoded[0].value == b"abc123"

    def test_raw_hex_type(self):
        encoded = encode_fields([TTLVField(9, TYPE_RAW_HEX, b"\x01\x02\x03")])
        decoded = decode_fields(encoded)
        assert decoded == [TTLVField(9, TYPE_RAW_HEX, b"\x01\x02\x03")]

    def test_empty_bytes(self):
        encoded = encode_fields([TTLVField(1, TYPE_BYTES, b"")])
        decoded = decode_fields(encoded)
        assert decoded == [TTLVField(1, TYPE_BYTES, b"")]


class TestStructRoundTrip:
    def test_nested_fields(self):
        nested = [TTLVField(1, TYPE_BOOL_TRUE, None), TTLVField(2, TYPE_NUMBER, 42)]
        encoded = encode_fields([TTLVField(10, TYPE_STRUCT, nested)])
        decoded = decode_fields(encoded)
        assert len(decoded) == 1
        assert decoded[0].id == 10
        assert decoded[0].type == TYPE_STRUCT
        # bool fields decode with value filled in from their type, unlike
        # the encoder input above which ignores it
        assert decoded[0].value == [
            TTLVField(1, TYPE_BOOL_TRUE, True),
            TTLVField(2, TYPE_NUMBER, 42),
        ]

    def test_empty_struct(self):
        encoded = encode_fields([TTLVField(10, TYPE_STRUCT, [])])
        decoded = decode_fields(encoded)
        assert decoded == [TTLVField(10, TYPE_STRUCT, [])]

    def test_deeply_nested_struct_rejected(self):
        inner = [TTLVField(1, TYPE_BOOL_TRUE, None)]
        for _ in range(21):
            inner = [TTLVField(1, TYPE_STRUCT, inner)]
        encoded = encode_fields([TTLVField(1, TYPE_STRUCT, inner)])
        with pytest.raises(ProtocolError):
            decode_fields(encoded)


class TestMultipleFields:
    def test_several_fields_in_sequence(self):
        fields = [
            TTLVField(1, TYPE_BOOL_TRUE, None),
            TTLVField(2, TYPE_NUMBER, 5),
            TTLVField(3, TYPE_BYTES, b"x"),
        ]
        encoded = encode_fields(fields)
        expected = [
            TTLVField(1, TYPE_BOOL_TRUE, True),
            TTLVField(2, TYPE_NUMBER, 5),
            TTLVField(3, TYPE_BYTES, b"x"),
        ]
        assert decode_fields(encoded) == expected


class TestMalformedInput:
    @pytest.mark.parametrize(
        "data",
        [
            b"\x00",  # half a field header
            b"\x00\x0a",  # number field with no marker byte
            b"\x00\x0a\x01\x00",  # number marker promising 2 value bytes, 1 present
            b"\x00\x0b\x00",  # bytes field with half a length prefix
            b"\x00\x0b\x00\x05ab",  # bytes field shorter than its length prefix
            b"\x00\x0c",  # struct field with no count
            b"\x00\x0c\x00\x02\x00\x09",  # struct promising 2 fields, 1 present
            b"\x00\x0e",  # unknown wire type 6
        ],
    )
    def test_decode_raises_protocol_error(self, data):
        with pytest.raises(ProtocolError):
            decode_fields(data)

    def test_number_wider_than_64_bits_raises_protocol_error(self):
        with pytest.raises(ProtocolError):
            encode_field(TTLVField(1, TYPE_NUMBER, 2**64))

    def test_frame_length_too_small_is_dropped_without_losing_the_next_frame(self):
        bad = b"\xaa\xaa\x00\x01\x00\x00\x00\x00\x00"
        good = encode_frame(cmd=17, payload=b"x", packet_id=1)
        assert [d.cmd for d in FrameDecoder().feed(bad + good)] == [17]


class TestIdList:
    def test_encodes_raw_ids_untyped(self):
        assert encode_id_list([1, 2, 300]) == struct.pack(">HHH", 1, 2, 300)


class TestFieldForProperty:
    def test_bool_true(self):
        assert field_for_property(5, "1", True) == TTLVField(5, TYPE_BOOL_TRUE, None)

    def test_bool_false(self):
        assert field_for_property(5, "1", False) == TTLVField(5, TYPE_BOOL_FALSE, None)

    def test_numeric_datatypes(self):
        for dt in ("2", "3", "4", "5", "7"):
            assert field_for_property(1, dt, 7) == TTLVField(1, TYPE_NUMBER, 7)

    def test_text_datatype(self):
        assert field_for_property(1, "6", "on") == TTLVField(1, TYPE_BYTES, "on")

    def test_raw_datatype(self):
        assert field_for_property(1, "11", b"\xff") == TTLVField(1, TYPE_RAW_HEX, b"\xff")

    def test_unsupported_datatype_raises(self):
        with pytest.raises(ProtocolError):
            field_for_property(1, "9", [1, 2])

    def test_named_datatypes_from_real_api(self):
        # The real userDeviceList/productTSL responses use these human-
        # readable names, confirmed against a real device — not the
        # numeric-string codes above, which are the app's internal
        # convention only.
        assert field_for_property(1, "BOOL", True) == TTLVField(1, TYPE_BOOL_TRUE, None)
        assert field_for_property(1, "BOOL", False) == TTLVField(1, TYPE_BOOL_FALSE, None)
        assert field_for_property(2, "ENUM", 3) == TTLVField(2, TYPE_NUMBER, 3)
        assert field_for_property(3, "INT", 5) == TTLVField(3, TYPE_NUMBER, 5)
        assert field_for_property(1, "TEXT", "on") == TTLVField(1, TYPE_BYTES, "on")
        assert field_for_property(1, "RAW", b"\xff") == TTLVField(1, TYPE_RAW_HEX, b"\xff")

    def test_named_datatype_case_insensitive(self):
        assert field_for_property(1, "bool", True) == TTLVField(1, TYPE_BOOL_TRUE, None)
        assert field_for_property(1, "Enum", 2) == TTLVField(1, TYPE_NUMBER, 2)


class TestFrameRoundTrip:
    def test_basic_frame(self):
        frame = encode_frame(cmd=17, payload=b"\x00\x01", packet_id=1000)
        decoder = FrameDecoder()
        decoded = decoder.feed(frame)
        assert len(decoded) == 1
        assert decoded[0].cmd == 17
        assert decoded[0].packet_id == 1000
        assert decoded[0].payload == b"\x00\x01"

    def test_empty_payload(self):
        frame = encode_frame(cmd=28722, payload=b"", packet_id=1001)
        decoded = FrameDecoder().feed(frame)
        assert decoded[0].cmd == 28722
        assert decoded[0].payload == b""

    def test_frame_bytes_match_wire_format(self):
        # AA AA | length=7 | checksum=sum(03 E8 00 11 00 01)=FD | packetId | cmd | payload
        frame = encode_frame(cmd=17, payload=b"\x00\x01", packet_id=1000)
        assert frame.hex() == "aaaa0007fd03e800110001"

    def test_stuffing_bytes_match_wire_format(self):
        # The first payload AA is followed by AA, so a 55 is inserted after it.
        frame = encode_frame(cmd=1, payload=b"\xaa\xaa", packet_id=1)
        assert frame.hex() == "aaaa00075600010001aa55aa"

    def test_multiple_frames_in_one_feed(self):
        frame1 = encode_frame(cmd=17, payload=b"a", packet_id=1000)
        frame2 = encode_frame(cmd=19, payload=b"bb", packet_id=1001)
        decoded = FrameDecoder().feed(frame1 + frame2)
        assert [d.cmd for d in decoded] == [17, 19]
        assert [d.payload for d in decoded] == [b"a", b"bb"]

    def test_frame_split_across_multiple_feeds(self):
        frame = encode_frame(cmd=50, payload=b"status", packet_id=1234)
        decoder = FrameDecoder()
        assert decoder.feed(frame[:5]) == []
        assert decoder.feed(frame[5:10]) == []
        decoded = decoder.feed(frame[10:])
        assert len(decoded) == 1
        assert decoded[0].cmd == 50
        assert decoded[0].payload == b"status"

    def test_garbage_before_valid_frame_is_discarded(self):
        frame = encode_frame(cmd=17, payload=b"x", packet_id=1)
        decoded = FrameDecoder().feed(b"\x01\x02\x03garbage" + frame)
        assert len(decoded) == 1
        assert decoded[0].cmd == 17

    def test_trailing_lone_sync_byte_preserved_across_feeds(self):
        frame = encode_frame(cmd=17, payload=b"x", packet_id=1)
        decoder = FrameDecoder()
        # Feed one stray 0xAA, then the rest of a real frame appended after
        # it — the decoder must not discard that trailing 0xAA, since it
        # could be (and here, is) the start of the next sync marker.
        assert decoder.feed(b"\xaa") == []
        decoded = decoder.feed(frame[1:])
        assert len(decoded) == 1
        assert decoded[0].cmd == 17

    def test_checksum_mismatch_is_dropped_without_losing_the_next_frame(self):
        bad = bytearray(encode_frame(cmd=17, payload=b"x", packet_id=1))
        bad[4] ^= 0xFF  # the checksum byte
        good = encode_frame(cmd=19, payload=b"y", packet_id=2)
        assert [d.cmd for d in FrameDecoder().feed(bytes(bad) + good)] == [19]

    def test_payload_containing_sync_like_bytes_round_trips(self):
        # Payload deliberately contains AA-AA and AA-55 sequences that would
        # be mistaken for a sync marker / an already-escaped byte if the
        # stuffing weren't applied and reversed correctly.
        tricky_payload = b"\xaa\xaa\xaa\x55\x00\xaa"
        frame = encode_frame(cmd=99, payload=tricky_payload, packet_id=42)
        assert SYNC not in frame[2:]
        decoded = FrameDecoder().feed(frame)
        assert len(decoded) == 1
        assert decoded[0].payload == tricky_payload

    def test_packet_id_round_trips(self):
        frame = encode_frame(cmd=1, payload=b"", packet_id=54321)
        decoded = FrameDecoder().feed(frame)
        assert decoded[0].packet_id == 54321
