"""IEEE 802.15.4 MAC frame parsing (2003/2006/2015 frame versions, as used by Thread)."""
import struct
from dataclasses import dataclass

FT_BEACON, FT_DATA, FT_ACK, FT_CMD, FT_MULTI = 0, 1, 2, 3, 5
FT_NAMES = {0: "beacon", 1: "data", 2: "ack", 3: "cmd", 5: "multipurpose"}
MIC_LEN = {0: 0, 1: 4, 2: 8, 3: 16, 4: 0, 5: 4, 6: 8, 7: 16}
CMD_NAMES = {1: "Association Request", 2: "Association Response", 3: "Disassociation",
             4: "Data Request", 5: "PAN ID Conflict", 6: "Orphan", 7: "Beacon Request",
             8: "Coordinator Realignment"}
BROADCAST = 0xFFFF


class ParseError(Exception):
    pass


@dataclass
class Frame:
    raw: bytes
    ftype: int = 0
    security: bool = False
    pending: bool = False
    ack_req: bool = False
    version: int = 0
    seq: int | None = None
    dst_pan: int | None = None
    src_pan: int | None = None
    dst: int | bytes | None = None   # int = short address, bytes = 8-byte extended (big-endian)
    src: int | bytes | None = None
    sec_level: int = 0
    key_id_mode: int = 0
    frame_counter: int | None = None
    key_source: bytes = b""
    key_index: int | None = None
    hdr_len: int = 0                 # bytes covered as AAD (MAC header incl. aux sec header + header IEs)
    payload: bytes = b""             # MAC payload as on air (ciphertext if secured), MIC removed
    mic: bytes = b""
    payload_ies: bool = False        # payload IEs precede the payload (inside the encrypted part)

    @property
    def pan(self):
        return self.dst_pan if self.dst_pan is not None else self.src_pan


def _pan_presence(version, dmode, smode, comp):
    if version < 2:
        return dmode != 0, smode != 0 and not comp
    if dmode == 0 and smode == 0:
        return comp, False
    if dmode and not smode:
        return not comp, False
    if smode and not dmode:
        return False, not comp
    if dmode == 3 and smode == 3:
        return not comp, False
    return True, not comp


def _addr(b, pos, mode):
    if mode == 2:
        if pos + 2 > len(b):
            raise ParseError("short address truncated")
        return struct.unpack_from("<H", b, pos)[0], pos + 2
    if mode == 3:
        if pos + 8 > len(b):
            raise ParseError("ext address truncated")
        return bytes(b[pos:pos + 8][::-1]), pos + 8
    if mode == 0:
        return None, pos
    raise ParseError("reserved addressing mode")


def parse(b: bytes) -> Frame:
    if len(b) < 3:
        raise ParseError("too short")
    fcf = struct.unpack_from("<H", b)[0]
    f = Frame(raw=bytes(b))
    f.ftype = fcf & 7
    f.security = bool(fcf >> 3 & 1)
    f.pending = bool(fcf >> 4 & 1)
    f.ack_req = bool(fcf >> 5 & 1)
    comp = bool(fcf >> 6 & 1)
    seq_supp = bool(fcf >> 8 & 1)
    ie_present = bool(fcf >> 9 & 1)
    dmode = fcf >> 10 & 3
    f.version = fcf >> 12 & 3
    smode = fcf >> 14 & 3
    pos = 2
    if not (f.version == 2 and seq_supp):
        f.seq = b[pos]
        pos += 1
    if f.ftype == FT_ACK and f.version < 2:
        f.hdr_len = pos
        return f
    dp, sp = _pan_presence(f.version, dmode, smode, comp)
    if dp:
        f.dst_pan = struct.unpack_from("<H", b, pos)[0]
        pos += 2
    f.dst, pos = _addr(b, pos, dmode)
    if sp:
        f.src_pan = struct.unpack_from("<H", b, pos)[0]
        pos += 2
    elif smode and f.version < 2 and comp:
        f.src_pan = f.dst_pan
    f.src, pos = _addr(b, pos, smode)

    if f.security:
        if pos >= len(b):
            raise ParseError("aux security header truncated")
        sc = b[pos]
        pos += 1
        f.sec_level = sc & 7
        f.key_id_mode = sc >> 3 & 3
        fc_supp = f.version == 2 and bool(sc >> 5 & 1)
        if not fc_supp:
            if pos + 4 > len(b):
                raise ParseError("frame counter truncated")
            f.frame_counter = struct.unpack_from("<I", b, pos)[0]
            pos += 4
        ks = {0: 0, 1: 0, 2: 4, 3: 8}[f.key_id_mode]
        f.key_source = bytes(b[pos:pos + ks])
        pos += ks
        if f.key_id_mode:
            f.key_index = b[pos]
            pos += 1

    if ie_present:
        while pos + 2 <= len(b):
            h = struct.unpack_from("<H", b, pos)[0]
            ln, eid = h & 0x7F, h >> 7 & 0xFF
            pos += 2 + ln
            if eid == 0x7E:          # HT1: payload IEs follow
                f.payload_ies = True
                break
            if eid == 0x7F:          # HT2: payload follows
                break
    f.hdr_len = pos
    mic = MIC_LEN[f.sec_level] if f.security else 0
    if pos + mic > len(b):
        raise ParseError("payload truncated")
    f.payload = bytes(b[pos:len(b) - mic])
    f.mic = bytes(b[len(b) - mic:]) if mic else b""
    return f


def skip_payload_ies(p: bytes) -> bytes:
    pos = 0
    while pos + 2 <= len(p):
        h = struct.unpack_from("<H", p, pos)[0]
        ln, gid = h & 0x7FF, h >> 11 & 0xF
        pos += 2 + ln
        if gid == 0xF:
            break
    return p[pos:]


def fmt_addr(a):
    if a is None:
        return "-"
    if isinstance(a, int):
        return f"0x{a:04x}"
    return a.hex()
