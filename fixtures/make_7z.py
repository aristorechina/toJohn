"""Build a minimal AES-256-encrypted .7z archive by hand.

The archive layout produced here mirrors the simplest encrypted case that
run/7z2john.pl handles:
- one folder with a single AES-256 coder (06F10701), no compression
- the header is unencrypted and sits right after the 32-byte signature header
- the packed (encrypted) data comes after the header

Usage: uv run --no-project python fixtures/make_7z.py
Writes: fixtures/sevenz/test.7z and prints the expected $7z$ fields.
"""
import struct
import zlib


def encode_number(n: int) -> bytes:
    """Canonical 7z variable-length number encoding."""
    if n < 0x80:
        return bytes([n])
    extra = 0
    while n >> (7 - extra) != 0:
        extra += 1
        if extra >= 8:
            break
    first = 0x80
    for i in range(1, extra + 1):
        first |= 0x80 >> i
    first |= (n >> (8 * extra)) & ((1 << (7 - extra)) - 1)
    out = [first]
    for i in range(extra):
        out.append((n >> (8 * i)) & 0xFF)
    return bytes(out)


SALT = bytes(((i * 7 + 5) % 256) for i in range(16))
IV = bytes(((i * 3 + 9) % 256) for i in range(16))
CYCLES = 19
DATA = bytes(((i * 5 + 7) % 256) for i in range(16))  # one AES block
UNPACK_SIZE = 16
CRC = zlib.crc32(DATA) & 0xFFFFFFFF

# coder attributes: b0 = cycles | 0x80 (salt present) | 0x40 (iv present),
# then salt/iv byte-count nibble byte (0 = 16 salt / 16 iv here), then salt+iv
b0 = (CYCLES & 0x3F) | 0x80 | 0x40
attrs = bytes([b0, 0x00]) + SALT + IV

# ---- UnpackInfo: one folder, one AES coder, one output stream ----
folder = b""
folder += encode_number(1)      # num coders
folder += bytes([0x24])         # main byte: idsize=4, 0x20 = props follow
folder += b"\x06\xf1\x07\x01"   # AES-256 + SHA-256 coder id
folder += encode_number(len(attrs))
folder += attrs

ui = b""
ui += encode_number(0x0B)       # kFolder
ui += encode_number(1)          # num folders
ui += b"\x00"                   # external = 0
ui += folder
ui += encode_number(0x0e)       # kUnpackSize (main output)
ui += encode_number(UNPACK_SIZE)
ui += encode_number(0x00)       # kEnd

# ---- SubStreamsInfo: one stream, CRC defined ----
ss = b""
ss += encode_number(0x0D)       # kNumUnpackStream
ss += encode_number(1)
ss += encode_number(0x0A)       # kCRC
ss += b"\x01"                   # all defined
ss += struct.pack("<I", CRC)
ss += encode_number(0x00)       # kEnd

si = b""
si += encode_number(0x06)       # kPackInfo
si += encode_number(75)         # pack_pos: data lives after the 75-byte header
si += encode_number(1)          # num pack streams
si += encode_number(0x09)       # kSize
si += encode_number(len(DATA))  # pack size
si += encode_number(0x00)       # kEnd
si += encode_number(0x07)       # kUnpackInfo
si += ui
si += encode_number(0x08)       # kSubStreamsInfo
si += ss
si += encode_number(0x00)       # kEnd

hdr = b""
hdr += encode_number(0x01)      # kHeader
hdr += encode_number(0x04)      # kMainStreamsInfo
hdr += si
hdr += encode_number(0x00)      # kEnd

# ---- signature header ----
sig = bytearray()
sig += b"7z\xbc\xaf\x27\x1c"
sig += b"\x00\x04"                                          # version 0.4
sig += struct.pack("<I", 0)                                 # StartHeaderCRC placeholder
sig += struct.pack("<Q", 0)                                 # next header offset
sig += struct.pack("<Q", len(hdr))                          # next header size
sig += struct.pack("<I", zlib.crc32(hdr) & 0xFFFFFFFF)      # next header CRC
shcrc = zlib.crc32(bytes(sig[12:32])) & 0xFFFFFFFF
sig[8:12] = struct.pack("<I", shcrc)

out = bytes(sig) + hdr + DATA
open("fixtures/sevenz/test.7z", "wb").write(out)
print("7z written:", len(out))
print(
    "expected fields: type=0 cycles=%d salt=%s iv=%s crc=%08x data=%s unpack=%d"
    % (CYCLES, SALT.hex(), IV.hex(), CRC, DATA.hex(), UNPACK_SIZE)
)
