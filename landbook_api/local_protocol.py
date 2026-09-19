"""Landbook local-LAN control wire protocol — binary TTLV framing.

This is a completely different protocol from the cloud MQTT channel in
mqtt_client.py: a custom binary format over a raw TCP socket, used by the
Landbook app to control a device directly over the local network instead of
round-tripping through the cloud. The app prefers this path whenever it can
reach the device's LAN IP (see local_client.py's module docstring for how a
device is found and connected to), falling back to cloud MQTT otherwise.

No public documentation exists for any of this — it was reverse-engineered
from the Landbook Android app's Quectel IoT SDK classes (obfuscated names
`bs`/`DecodeTools`/`TTLVData` in the app's dex, both the encoder and the
decoder having been read to confirm each byte is produced/consumed the same
way on both ends).

Frame layout (all multi-byte integers big-endian):

    AA AA | length:u16 | checksum:u8 | packetId:u16 | cmd:u16 | payload

`length` = 5 + len(payload) (i.e. checksum+packetId+cmd+payload).
`checksum` = sum(packetId + cmd + payload bytes) & 0xFF — a plain additive
checksum, not a CRC.

Byte-stuffing: since the two leading 0xAA bytes are how a receiver finds the
start of the next frame in a TCP stream, any occurrence of 0xAA followed by
0x55 or 0xAA *after* that fixed header (i.e. from the length field onward)
has an extra 0x55 inserted right after the 0xAA. This escapes both a literal
"AA AA" that would otherwise look like a new sync marker, and a literal
"AA 55" that would otherwise look like an already-escaped one. Decoding
reverses this: any 0x55 immediately following an 0xAA is dropped.

Payload encoding is TTLV (Tag-Type-Length-Value): each field is a 2-byte
header packing a 13-bit field id and a 3-bit type, `(id << 3) | type`,
followed by a type-dependent value:

- type 0 / 1: a boolean flag — no value bytes, the type IS the value.
- type 2: a number (int or a decimal-scaled float), encoded as one marker
  byte (sign bit, 4-bit decimal-digit count for floats, 3-bit
  value-byte-count minus one) followed by the minimal big-endian magnitude
  bytes.
- type 3 / 5: length-prefixed raw bytes (a 2-byte big-endian byte count,
  then that many bytes) — used for UTF-8 strings (3) and raw hex blobs (5).
- type 4: a nested struct — a 2-byte big-endian *count* of nested fields
  (not a byte length), then that many fields recursively encoded the same
  way.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

SYNC = b"\xaa\xaa"

# TTLV wire types (3 bits, packed with a 13-bit field id into a 2-byte header)
TYPE_BOOL_FALSE = 0
TYPE_BOOL_TRUE = 1
TYPE_NUMBER = 2
TYPE_BYTES = 3
TYPE_STRUCT = 4
TYPE_RAW_HEX = 5

_MAX_STRUCT_DEPTH = 20


class ProtocolError(ValueError):
    """A frame or TTLV payload was malformed or failed its checksum."""


@dataclass
class TTLVField:
    id: int
    type: int
    value: Any


@dataclass
class DecodedFrame:
    packet_id: int
    cmd: int
    payload: bytes


# ----------------------------------------------------------------------
# TSL dataType -> TTLV wire type
# ----------------------------------------------------------------------

# Maps the `dataType` string on a TSL property (from api.get_tsl) to the
# TTLV wire type used to encode/decode its value locally. Source: the app's
# DataModelConvertUtil field-encoder dispatch (dataType "1"=BOOL,
# "2"/"3"/"4"/"5"/"7"=numeric family, "6"=TEXT, "8"/"9"=STRUCT/ARRAY,
# "11"=RAW hex). "8"/"9" (nested struct/array properties) aren't mapped
# here — build a TYPE_STRUCT TTLVField with a `value` list of nested
# TTLVFields directly if a device ever needs one; no OmniBreeze fan
# property observed so far has used them.
_DATATYPE_TO_TTLV_TYPE = {
    "1": None,  # bool — caller picks TYPE_BOOL_TRUE/FALSE from the value itself
    "2": TYPE_NUMBER,
    "3": TYPE_NUMBER,
    "4": TYPE_NUMBER,
    "5": TYPE_NUMBER,
    "7": TYPE_NUMBER,
    "6": TYPE_BYTES,
    "11": TYPE_RAW_HEX,
}


def field_for_property(prop_id: int, data_type: str, value: Any) -> TTLVField:
    """Build a TTLVField for a TSL property's numeric `id` (NOT its string
    `code` — that's only used by the cloud MQTT JSON protocol), `dataType`,
    and current value."""
    if data_type == "1":
        return TTLVField(prop_id, TYPE_BOOL_TRUE if value else TYPE_BOOL_FALSE, None)
    ttlv_type = _DATATYPE_TO_TTLV_TYPE.get(data_type)
    if ttlv_type is None:
        raise ProtocolError(f"unsupported TSL dataType for local control: {data_type!r}")
    return TTLVField(prop_id, ttlv_type, value)


# ----------------------------------------------------------------------
# TTLV field encode / decode
# ----------------------------------------------------------------------


def _encode_number(value: float) -> bytes:
    if isinstance(value, float):
        sign = 1 if value < 0 else 0
        text = f"{abs(value):.15f}".rstrip("0").rstrip(".")
        int_part, _, frac_part = text.partition(".")
        count = len(frac_part)
        digits = (int_part + frac_part) or "0"
        magnitude = int(digits)
    else:
        sign = 1 if value < 0 else 0
        magnitude = abs(int(value))
        count = 0

    if count > 0xF:
        raise ProtocolError(f"value has too many decimal digits for TTLV encoding: {value!r}")

    value_bytes = magnitude.to_bytes(8, "big").lstrip(b"\x00") or b"\x00"
    if len(value_bytes) > 8:
        raise ProtocolError(f"value too large for TTLV numeric encoding: {value!r}")

    marker = (sign << 7) | ((count & 0xF) << 3) | (len(value_bytes) - 1)
    return bytes([marker]) + value_bytes


def _decode_number(data: bytes, offset: int) -> tuple[int | float, int]:
    marker = data[offset]
    sign = (marker >> 7) & 0x1
    count = (marker >> 3) & 0xF
    nbytes = (marker & 0x7) + 1
    start = offset + 1
    end = start + nbytes
    magnitude = int.from_bytes(data[start:end], "big")
    if sign:
        magnitude = -magnitude
    if count:
        scaled = Decimal(magnitude) / (Decimal(10) ** count)
        value: int | float = float(
            scaled.quantize(Decimal(1).scaleb(-count), rounding=ROUND_HALF_UP)
        )
    else:
        value = magnitude
    return value, end


def encode_field(f: TTLVField) -> bytes:
    header = struct.pack(">H", ((f.id << 3) & 0xFFF8) | (f.type & 0x7))
    if f.type in (TYPE_BOOL_FALSE, TYPE_BOOL_TRUE):
        return header
    if f.type == TYPE_NUMBER:
        return header + _encode_number(f.value)
    if f.type in (TYPE_BYTES, TYPE_RAW_HEX):
        raw = f.value if isinstance(f.value, (bytes, bytearray)) else str(f.value).encode("utf-8")
        return header + struct.pack(">H", len(raw)) + bytes(raw)
    if f.type == TYPE_STRUCT:
        items: list[TTLVField] = f.value or []
        body = b"".join(encode_field(item) for item in items)
        return header + struct.pack(">H", len(items)) + body
    raise ProtocolError(f"unsupported TTLV type {f.type}")


def encode_fields(fields: list[TTLVField]) -> bytes:
    return b"".join(encode_field(f) for f in fields)


def encode_id_list(ids: list[int]) -> bytes:
    """The untyped payload shape used by CMD_READ: just the raw 2-byte
    field ids, no type tag and no value — a plain "give me these
    properties" request."""
    return b"".join(struct.pack(">H", i & 0xFFFF) for i in ids)


def _decode_one_field(data: bytes, offset: int, depth: int) -> tuple[TTLVField, int]:
    if depth > _MAX_STRUCT_DEPTH:
        raise ProtocolError("TTLV struct nesting too deep")
    if offset + 2 > len(data):
        raise ProtocolError("truncated TTLV field header")
    header = struct.unpack_from(">H", data, offset)[0]
    field_id = (header >> 3) & 0x1FFF
    field_type = header & 0x7
    offset += 2

    if field_type in (TYPE_BYTES, TYPE_RAW_HEX):
        length = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        value: Any = bytes(data[offset : offset + length])
        offset += length
    elif field_type in (TYPE_BOOL_FALSE, TYPE_BOOL_TRUE):
        value = field_type == TYPE_BOOL_TRUE
    elif field_type == TYPE_NUMBER:
        value, offset = _decode_number(data, offset)
    elif field_type == TYPE_STRUCT:
        count = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        items = []
        for _ in range(count):
            item, offset = _decode_one_field(data, offset, depth + 1)
            items.append(item)
        value = items
    else:
        raise ProtocolError(f"unsupported TTLV type {field_type}")

    return TTLVField(field_id, field_type, value), offset


def decode_fields(data: bytes) -> list[TTLVField]:
    offset = 0
    fields = []
    while offset < len(data):
        f, offset = _decode_one_field(data, offset, depth=0)
        fields.append(f)
    return fields


# ----------------------------------------------------------------------
# Frame encode / decode
# ----------------------------------------------------------------------


def _checksum(data: bytes) -> int:
    return sum(data) & 0xFF


def _stuff(frame: bytes) -> bytes:
    # The literal 2-byte sync marker (and the byte immediately after it) is
    # never a stuffing candidate — only pairs starting at offset 2 onward
    # are escaped, matching the encoder this mirrors.
    out = bytearray(frame[:2])
    i = 2
    n = len(frame)
    while i < n:
        b = frame[i]
        out.append(b)
        if b == 0xAA and i + 1 < n and frame[i + 1] in (0x55, 0xAA):
            out.append(0x55)
        i += 1
    return bytes(out)


def _unstuff(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        out.append(b)
        if b == 0xAA and i + 1 < n and data[i + 1] == 0x55:
            i += 2
        else:
            i += 1
    return bytes(out)


def encode_frame(cmd: int, payload: bytes, packet_id: int) -> bytes:
    body = struct.pack(">HH", packet_id & 0xFFFF, cmd & 0xFFFF) + payload
    checksum = _checksum(body)
    length_field = len(body) + 1  # + the checksum byte itself
    frame = SYNC + struct.pack(">H", length_field) + bytes([checksum]) + body
    return _stuff(frame)


def _parse_frame(raw: bytes) -> DecodedFrame:
    checksum = raw[4]
    body = raw[5:]
    if _checksum(body) != checksum:
        raise ProtocolError("frame checksum mismatch")
    packet_id, cmd = struct.unpack_from(">HH", raw, 5)
    return DecodedFrame(packet_id=packet_id, cmd=cmd, payload=raw[9:])


class FrameDecoder:
    """Reassembles frames out of a byte stream (TCP or UDP).

    Mirrors the app's TCP-path reassembly: each newly-fed chunk is
    de-stuffed independently before being appended to a persistent buffer,
    then complete frames are sliced off the front of that buffer as they
    become available. Feed it whatever bytes a socket read produces, in
    order; get back zero or more fully-decoded frames.
    """

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, chunk: bytes) -> list[DecodedFrame]:
        self._buf.extend(_unstuff(chunk))
        frames = []
        while True:
            frame = self._try_extract_one()
            if frame is None:
                break
            frames.append(frame)
        return frames

    def _try_extract_one(self) -> DecodedFrame | None:
        idx = self._buf.find(SYNC)
        if idx == -1:
            # Keep a lone trailing 0xAA in case it's the first half of the
            # next sync marker split across reads; anything else preceding
            # it is undecodable garbage.
            if self._buf and self._buf[-1] == 0xAA:
                del self._buf[:-1]
            else:
                self._buf.clear()
            return None
        if idx > 0:
            del self._buf[:idx]
        if len(self._buf) < 9:
            return None
        length_field = struct.unpack_from(">H", self._buf, 2)[0]
        total = length_field + 4
        if len(self._buf) < total:
            return None
        raw = bytes(self._buf[:total])
        del self._buf[:total]
        return _parse_frame(raw)
