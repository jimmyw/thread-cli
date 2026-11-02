"""6LoWPAN (RFC 4944 / RFC 6282) decompression into plain IPv6 packets, and IPv6 parsing."""
import ipaddress
import struct
from dataclasses import dataclass, field

LL_PREFIX = bytes.fromhex("fe80000000000000")
UNKNOWN_PREFIX = bytes(8)
RLOC_IID_HEAD = bytes.fromhex("000000fffe00")


class LowpanError(Exception):
    pass


def mac_iid(addr):
    if isinstance(addr, int):
        return RLOC_IID_HEAD + addr.to_bytes(2, "big")
    if isinstance(addr, bytes) and len(addr) == 8:
        return bytes([addr[0] ^ 0x02]) + addr[1:]
    return None


def iid_to_ext(iid: bytes) -> bytes:
    return bytes([iid[0] ^ 0x02]) + iid[1:]


@dataclass
class Lowpan:
    """Result of stripping mesh/broadcast/fragment headers."""
    mesh_src: object = None      # originator (short int / ext bytes) if a mesh header was present
    mesh_dst: object = None
    hops_left: int | None = None
    ipv6: bytes | None = None    # full uncompressed IPv6 packet (None while fragments are pending)
    fragment: str = ""           # "", "first", "next"
    missing_ctx: set = field(default_factory=set)


def _be16(b, p):
    return (b[p] << 8) | b[p + 1]


def _ucast(b, pos, ac, am, prefix, mac):
    if ac == 0 and am == 0:
        return bytes(b[pos:pos + 16]), pos + 16
    if ac == 1 and am == 0:
        return bytes(16), pos
    if am == 1:
        iid = bytes(b[pos:pos + 8])
        pos += 8
    elif am == 2:
        iid = RLOC_IID_HEAD + bytes(b[pos:pos + 2])
        pos += 2
    else:
        iid = mac_iid(mac)
        if iid is None:
            raise LowpanError("address elided but no link-layer address")
    return prefix + iid, pos


def _iphc(b, pos, mac_src, mac_dst, ctx, missing):
    """Decompress one IPHC header (plus NHC chain). Returns (bytes, pos, fixups)."""
    if pos >= len(b):
        raise LowpanError("empty")
    if b[pos] == 0x41:                       # uncompressed IPv6
        return bytearray(), pos + 1, []
    if b[pos] >> 5 != 0b011:
        raise LowpanError(f"unknown dispatch 0x{b[pos]:02x}")
    h0, h1 = b[pos], b[pos + 1]
    pos += 2
    tf, nh, hlim = h0 >> 3 & 3, h0 >> 2 & 1, h0 & 3
    cid, sac, sam, m, dac, dam = h1 >> 7, h1 >> 6 & 1, h1 >> 4 & 3, h1 >> 3 & 1, h1 >> 2 & 1, h1 & 3
    sci = dci = 0
    if cid:
        sci, dci = b[pos] >> 4, b[pos] & 0xF
        pos += 1
    ecn = dscp = flow = 0
    if tf == 0:
        ecn, dscp = b[pos] >> 6, b[pos] & 0x3F
        flow = (b[pos + 1] & 0xF) << 16 | b[pos + 2] << 8 | b[pos + 3]
        pos += 4
    elif tf == 1:
        ecn = b[pos] >> 6
        flow = (b[pos] & 0xF) << 16 | b[pos + 1] << 8 | b[pos + 2]
        pos += 3
    elif tf == 2:
        ecn, dscp = b[pos] >> 6, b[pos] & 0x3F
        pos += 1
    nxt = None
    if nh == 0:
        nxt = b[pos]
        pos += 1
    if hlim == 0:
        hl = b[pos]
        pos += 1
    else:
        hl = {1: 1, 2: 64, 3: 255}[hlim]

    def prefix_for(ac, ci):
        if not ac:
            return LL_PREFIX
        p = ctx.get(ci)
        if p is None:
            missing.add(ci)
            return UNKNOWN_PREFIX
        return p

    src, pos = _ucast(b, pos, sac, sam, prefix_for(sac, sci), mac_src)
    if not m:
        dst, pos = _ucast(b, pos, dac, dam, prefix_for(dac, dci), mac_dst)
    elif not dac:
        if dam == 0:
            dst = bytes(b[pos:pos + 16]); pos += 16
        elif dam == 1:
            dst = bytes([0xFF, b[pos]]) + bytes(9) + bytes(b[pos + 1:pos + 6]); pos += 6
        elif dam == 2:
            dst = bytes([0xFF, b[pos]]) + bytes(11) + bytes(b[pos + 1:pos + 4]); pos += 4
        else:
            dst = bytes([0xFF, 0x02]) + bytes(13) + bytes([b[pos]]); pos += 1
    else:
        if dam != 0:
            raise LowpanError("reserved multicast DAM")
        p = prefix_for(1, dci)
        dst = bytes([0xFF, b[pos], b[pos + 1], 64]) + p + bytes(b[pos + 2:pos + 6]); pos += 6

    tc = dscp << 2 | ecn
    out = bytearray(40)
    out[0] = 0x60 | tc >> 4
    out[1] = (tc & 0xF) << 4 | flow >> 16
    out[2], out[3] = flow >> 8 & 0xFF, flow & 0xFF
    out[7] = hl
    out[8:24], out[24:40] = src, dst
    fix = [("ip", 0)]
    nh_pos = 6
    if nxt is not None:
        out[6] = nxt
        return out, pos, fix
    while True:
        d = b[pos]
        if d & 0xF8 == 0xF0:                 # UDP NHC
            out[nh_pos] = 17
            c, p = d >> 2 & 1, d & 3
            pos += 1
            if p == 0:
                sp, dp = _be16(b, pos), _be16(b, pos + 2); pos += 4
            elif p == 1:
                sp, dp = _be16(b, pos), 0xF000 | b[pos + 2]; pos += 3
            elif p == 2:
                sp, dp = 0xF000 | b[pos], _be16(b, pos + 1); pos += 3
            else:
                sp, dp = 0xF0B0 | b[pos] >> 4, 0xF0B0 | b[pos] & 0xF; pos += 1
            ck = 0
            if not c:
                ck = _be16(b, pos); pos += 2
            fix.append(("udp", len(out)))
            out += struct.pack(">HHHH", sp, dp, 0, ck)
            return out, pos, fix
        if d & 0xF0 == 0xE0:                 # extension header NHC
            eid, n = d >> 1 & 7, d & 1
            pos += 1
            proto = {0: 0, 1: 43, 2: 44, 3: 60, 4: 135, 7: 41}.get(eid)
            if proto is None:
                raise LowpanError(f"reserved NHC EID {eid}")
            out[nh_pos] = proto
            if eid == 7:                     # IPv6-in-IPv6: inner IPHC follows
                inner, pos, ifix = _iphc(b, pos, mac_src, mac_dst, ctx, missing)
                base = len(out)
                out += inner
                fix += [(k, s + base) for k, s in ifix]
                return out, pos, fix
            inline_nxt = None
            if n == 0:
                inline_nxt = b[pos]; pos += 1
            ln = b[pos]; pos += 1
            data = bytes(b[pos:pos + ln]); pos += ln
            eh = bytearray(2) + data
            pad = -len(eh) % 8
            if pad == 1:
                eh += b"\x00"
            elif pad > 1:
                eh += bytes([1, pad - 2]) + bytes(pad - 2)
            eh[1] = len(eh) // 8 - 1
            nh_pos = len(out)
            out += eh
            if n == 0:
                out[nh_pos] = inline_nxt
                return out, pos, fix
            continue
        raise LowpanError(f"unknown NHC 0x{d:02x}")


def _apply_fix(pkt: bytearray, fix):
    for kind, s in fix:
        if kind == "ip":
            struct.pack_into(">H", pkt, s + 4, max(0, len(pkt) - s - 40))
        else:
            struct.pack_into(">H", pkt, s + 4, max(0, len(pkt) - s))
    return bytes(pkt)


class Reassembler:
    def __init__(self):
        self.pending = {}

    def add(self, key, size, offset, chunk, fix, now):
        e = self.pending.get(key)
        if e is None or now - e["t"] > 5:
            e = self.pending[key] = {"buf": bytearray(size), "have": {}, "fix": None, "t": now}
        e["buf"][offset:offset + len(chunk)] = chunk[:max(0, size - offset)]
        e["have"][offset] = len(chunk)
        if fix is not None:
            e["fix"] = fix
        covered = sum(e["have"].values())
        if e["fix"] is not None and 0 in e["have"] and covered >= size:
            del self.pending[key]
            return _apply_fix(e["buf"][:size], e["fix"])
        # expire stale entries
        for k in [k for k, v in self.pending.items() if now - v["t"] > 5]:
            del self.pending[k]
        return None


def decode(payload: bytes, mac_src, mac_dst, ctx: dict, reasm: Reassembler, now: float) -> Lowpan:
    b = payload
    r = Lowpan()
    pos = 0
    if not b:
        raise LowpanError("empty payload")
    if b[0] >> 6 == 0b10:                    # mesh header
        v, fl, hops = b[0] >> 5 & 1, b[0] >> 4 & 1, b[0] & 0xF
        pos = 1
        if hops == 0xF:
            hops = b[pos]; pos += 1
        r.hops_left = hops
        if v:
            r.mesh_src = _be16(b, pos); pos += 2
        else:
            r.mesh_src = bytes(b[pos:pos + 8]); pos += 8
        if fl:
            r.mesh_dst = _be16(b, pos); pos += 2
        else:
            r.mesh_dst = bytes(b[pos:pos + 8]); pos += 8
        mac_src, mac_dst = r.mesh_src, r.mesh_dst
    if pos < len(b) and b[pos] == 0x50:      # LOWPAN_BC0
        pos += 2
    if pos >= len(b):
        raise LowpanError("no IPv6 payload")
    d = b[pos]
    if d & 0xF8 == 0xC0:                     # FRAG1
        size = (d & 7) << 8 | b[pos + 1]
        tag = _be16(b, pos + 2)
        pos += 4
        r.fragment = "first"
        hdr, pos, fix = _iphc(b, pos, mac_src, mac_dst, ctx, r.missing_ctx)
        chunk = bytes(hdr) + bytes(b[pos:])
        r.ipv6 = reasm.add((mac_src, tag, size), size, 0, chunk, fix, now)
        r._first_hdr = (bytes(hdr), fix, bytes(b[pos:]))  # for header-only use while incomplete
        return r
    if d & 0xF8 == 0xE0:                     # FRAGN
        size = (d & 7) << 8 | b[pos + 1]
        tag = _be16(b, pos + 2)
        off = b[pos + 4] * 8
        r.fragment = "next"
        r.ipv6 = reasm.add((mac_src, tag, size), size, off, bytes(b[pos + 5:]), None, now)
        return r
    hdr, pos, fix = _iphc(b, pos, mac_src, mac_dst, ctx, r.missing_ctx)
    if not hdr:                              # 0x41: inline IPv6
        r.ipv6 = bytes(b[pos:])
    else:
        r.ipv6 = _apply_fix(hdr + b[pos:], fix)
    return r


@dataclass
class IPv6:
    src: bytes
    dst: bytes
    hlim: int
    proto: int                    # final upper-layer protocol
    sport: int | None = None
    dport: int | None = None
    payload: bytes = b""          # UDP payload / ICMPv6 message
    icmp_type: int | None = None
    inner: "IPv6 | None" = None   # for IPv6-in-IPv6


def parse_ipv6(p: bytes) -> IPv6 | None:
    if len(p) < 40 or p[0] >> 4 != 6:
        return None
    pkt = IPv6(src=p[8:24], dst=p[24:40], hlim=p[7], proto=p[6])
    nh, pos = p[6], 40
    while nh in (0, 43, 60, 135) and pos + 2 <= len(p):
        nh, pos = p[pos], pos + (p[pos + 1] + 1) * 8
    if nh == 44 and pos + 8 <= len(p):
        nh, pos = p[pos], pos + 8
    pkt.proto = nh
    if nh == 41:
        pkt.inner = parse_ipv6(p[pos:])
    elif nh == 17 and pos + 8 <= len(p):
        pkt.sport, pkt.dport = struct.unpack_from(">HH", p, pos)
        pkt.payload = p[pos + 8:]
    elif nh == 58 and pos + 4 <= len(p):
        pkt.icmp_type = p[pos]
        pkt.payload = p[pos:]
    return pkt


def fmt_ip(a: bytes) -> str:
    return str(ipaddress.IPv6Address(a))


ICMP6_NAMES = {1: "Dest Unreachable", 2: "Packet Too Big", 3: "Time Exceeded", 128: "Echo Request",
               129: "Echo Reply", 133: "Router Solicitation", 134: "Router Advertisement",
               135: "Neighbor Solicitation", 136: "Neighbor Advertisement"}
UDP_PORTS = {19788: "MLE", 61631: "TMF/CoAP", 5683: "CoAP", 5353: "mDNS", 53: "DNS",
             5540: "Matter", 49191: "TMF", 61616: "TMF"}
