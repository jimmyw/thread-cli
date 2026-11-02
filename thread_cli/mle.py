"""Thread MLE (Mesh Link Establishment) decryption and TLV parsing."""
import struct
from dataclasses import dataclass, field

from . import crypto
from .dataset import parse_dataset
from .lowpan import LL_PREFIX, iid_to_ext

MLE_PORT = 19788

COMMANDS = {0: "Link Request", 1: "Link Accept", 2: "Link Accept And Request", 3: "Link Reject",
            4: "Advertisement", 5: "Update", 6: "Update Request", 7: "Data Request",
            8: "Data Response", 9: "Parent Request", 10: "Parent Response", 11: "Child ID Request",
            12: "Child ID Response", 13: "Child Update Request", 14: "Child Update Response",
            15: "Announce", 16: "Discovery Request", 17: "Discovery Response",
            18: "Link Metrics Mgmt Request", 19: "Link Metrics Mgmt Response",
            20: "Link Probe", 21: "Time Sync"}

THREAD_VERSIONS = {1: "1.0", 2: "1.1", 3: "1.2", 4: "1.3", 5: "1.4"}

T_SOURCE, T_MODE, T_TIMEOUT, T_CHALLENGE, T_RESPONSE, T_LL_FC = 0, 1, 2, 3, 4, 5
T_MLE_FC, T_ROUTE64, T_ADDR16, T_LEADER, T_NETDATA, T_TLV_REQ = 8, 9, 10, 11, 12, 13
T_CONNECTIVITY, T_LINK_MARGIN, T_STATUS, T_VERSION, T_ADDR_REG = 15, 16, 17, 18, 19
T_CHANNEL, T_PANID, T_ACTIVE_TS, T_PENDING_TS, T_ACTIVE_DS, T_PENDING_DS = 20, 21, 22, 23, 24, 25


@dataclass
class Mle:
    secured: bool
    ok: bool                      # decrypted and MIC verified (or unsecured)
    command: int | None = None
    key_seq: int | None = None
    frame_counter: int | None = None
    sender_ext: bytes | None = None
    tlvs: dict = field(default_factory=dict)   # type -> parsed value

    @property
    def name(self):
        return COMMANDS.get(self.command, f"cmd {self.command}") if self.command is not None else "?"


def decrypt(udp_payload: bytes, ip_src: bytes, ip_dst: bytes, km: crypto.KeyManager) -> Mle:
    p = udp_payload
    if not p:
        return Mle(False, False)
    if p[0] == 0xFF:                       # no security (Discovery)
        return _parse(Mle(False, True), p[1:])
    if p[0] != 0 or len(p) < 11 + 4:
        return Mle(True, False)
    sc = p[1]
    level, kim = sc & 7, sc >> 3 & 3
    fc = struct.unpack_from("<I", p, 2)[0]
    pos = 6
    seq = km.seq
    if kim == 2:
        seq = struct.unpack_from(">I", p, pos)[0]
        pos += 5
    elif kim == 1:
        pos += 1
    else:
        return Mle(True, False)
    aux = p[1:pos]
    mic_len = crypto_mic(level)
    body, mic = p[pos:len(p) - mic_len], p[len(p) - mic_len:]
    if ip_src[:8] != LL_PREFIX:
        return Mle(True, False, key_seq=seq, frame_counter=fc)
    ext = iid_to_ext(ip_src[8:])
    key = km.mle_key(seq)
    plain = crypto.ccm_decrypt(key, crypto.nonce(ext, fc, level), ip_src + ip_dst + aux, body, mic)
    m = Mle(True, plain is not None, key_seq=seq, frame_counter=fc, sender_ext=ext)
    if plain is None:
        return m
    return _parse(m, plain)


def crypto_mic(level):
    return {0: 0, 1: 4, 2: 8, 3: 16, 4: 0, 5: 4, 6: 8, 7: 16}[level]


def _parse(m: Mle, b: bytes) -> Mle:
    if not b:
        return m
    m.command = b[0]
    pos = 1
    while pos + 2 <= len(b):
        t, ln = b[pos], b[pos + 1]
        v = b[pos + 2:pos + 2 + ln]
        pos += 2 + ln
        try:
            m.tlvs[t] = _tlv(t, v)
        except (struct.error, IndexError, ValueError):
            m.tlvs[t] = v
    return m


def _tlv(t, v):
    if t in (T_SOURCE, T_ADDR16, T_VERSION, T_PANID):
        return struct.unpack(">H", v[:2])[0]
    if t in (T_MODE, T_LINK_MARGIN, T_STATUS):
        return v[0]
    if t in (T_TIMEOUT, T_LL_FC, T_MLE_FC):
        return struct.unpack(">I", v[:4])[0]
    if t == T_LEADER:
        pid, w, dv, sdv, lrid = struct.unpack(">IBBBB", v[:8])
        return {"partition": pid, "weighting": w, "data_version": dv, "stable_data_version": sdv,
                "leader_router_id": lrid}
    if t == T_ROUTE64:
        idseq, mask = v[0], v[1:9]
        ids = [i for i in range(64) if mask[i // 8] & (0x80 >> (i % 8))]
        routes = [{"router_id": rid, "lq_out": d >> 6 & 3, "lq_in": d >> 4 & 3, "cost": d & 0xF}
                  for rid, d in zip(ids, v[9:])]
        return {"id_seq": idseq, "routes": routes}
    if t == T_CONNECTIVITY:
        pp = (v[0] >> 6) & 3
        out = {"parent_priority": pp - 4 if pp & 2 else pp, "lq3": v[1], "lq2": v[2], "lq1": v[3],
               "leader_cost": v[4], "id_seq": v[5], "active_routers": v[6]}
        if len(v) >= 10:
            out["sed_buffer"] = struct.unpack_from(">H", v, 7)[0]
            out["sed_datagrams"] = v[9]
        return out
    if t == T_ADDR_REG:
        out, pos = [], 0
        while pos < len(v):
            c = v[pos]
            pos += 1
            if c & 0x80:
                out.append(("ctx", c & 0x0F, bytes(v[pos:pos + 8])))
                pos += 8
            else:
                out.append(("full", None, bytes(v[pos:pos + 16])))
                pos += 16
        return out
    if t == T_NETDATA:
        return parse_netdata(v)
    if t == T_CHANNEL:
        return struct.unpack_from(">H", v, 1)[0]
    if t in (T_ACTIVE_DS, T_PENDING_DS):
        return parse_dataset(v)
    if t in (T_ACTIVE_TS, T_PENDING_TS):
        return struct.unpack(">Q", v[:8])[0] >> 16
    return bytes(v)


def parse_netdata(b: bytes) -> dict:
    out = {"prefixes": [], "contexts": {}, "services": 0}
    pos = 0
    while pos + 2 <= len(b):
        t, ln = b[pos] >> 1, b[pos + 1]
        v = b[pos + 2:pos + 2 + ln]
        pos += 2 + ln
        if t == 5:
            out["services"] += 1
            continue
        if t != 1 or len(v) < 2:
            continue
        plen = v[1]
        nb = (plen + 7) // 8
        prefix = bytes(v[2:2 + nb]) + bytes(16 - nb)
        entry = {"prefix": prefix, "len": plen, "border_routers": [], "routes": [], "context": None}
        sub, spos = v[2 + nb:], 0
        while spos + 2 <= len(sub):
            st, sl = sub[spos] >> 1, sub[spos + 1]
            sv = sub[spos + 2:spos + 2 + sl]
            spos += 2 + sl
            if st == 0:
                for i in range(0, len(sv) - 2, 3):
                    entry["routes"].append(struct.unpack_from(">H", sv, i)[0])
            elif st == 2:
                for i in range(0, len(sv) - 3, 4):
                    rloc, flags = struct.unpack_from(">HH", sv, i)
                    entry["border_routers"].append({"rloc16": rloc, "flags": flags,
                                                    "on_mesh": bool(flags & 0x0100),
                                                    "default_route": bool(flags & 0x0200),
                                                    "slaac": bool(flags & 0x1000)})
            elif st == 3 and len(sv) >= 2:
                cid = sv[0] & 0x0F
                entry["context"] = cid
                out["contexts"][cid] = prefix[:8]
        out["prefixes"].append(entry)
    return out
