"""Device store: turns sniffed frames into per-device state."""
import collections
import ipaddress
from dataclasses import dataclass, field

from . import crypto, lowpan, mle, wpan
from .lowpan import LL_PREFIX, fmt_ip, iid_to_ext
from .spinel import RxFrame

ACK_WINDOW = 0.02   # an immediate ack follows its frame within ~1 ms; be generous for host timestamps


@dataclass
class Stats:
    frames: int = 0
    bad: int = 0
    thread: int = 0
    decrypted: int = 0
    undecryptable: int = 0
    foreign: int = 0
    acks_unmatched: int = 0


@dataclass
class Device:
    key: str
    ext: bytes | None = None
    rloc16: int | None = None
    pan: int | None = None
    thread: bool = False             # something from it decrypted with our key
    first: float = 0.0
    last: float = 0.0
    frames: int = 0
    counts: collections.Counter = field(default_factory=collections.Counter)
    rssi_last: int | None = None
    rssi_min: int | None = None
    rssi_max: int | None = None
    rssi_sum: float = 0.0
    rssi_n: int = 0
    rssi_hist: collections.deque = field(default_factory=lambda: collections.deque(maxlen=24))
    lqi_last: int | None = None
    mode: int | None = None
    timeout: int | None = None
    version: int | None = None
    leader: dict | None = None
    route: dict | None = None
    connectivity: dict | None = None
    link_margin: int | None = None
    mle_last: tuple | None = None    # (name, time)
    mle_counts: collections.Counter = field(default_factory=collections.Counter)
    addresses: dict = field(default_factory=dict)     # ip str -> origin ("registered", "seen")
    mac_fc: int | None = None
    mle_fc: int | None = None
    key_seq: int | None = None
    channel: int | None = None
    last_frame: str = ""
    ping: object = None

    def rx(self, f: RxFrame):
        self.last = f.t
        if not self.first:
            self.first = f.t
        self.frames += 1
        if f.channel:
            self.channel = f.channel
        if f.rssi is not None:
            r = f.rssi
            self.rssi_last = r
            self.rssi_min = r if self.rssi_min is None else min(self.rssi_min, r)
            self.rssi_max = r if self.rssi_max is None else max(self.rssi_max, r)
            self.rssi_sum += r
            self.rssi_n += 1
            self.rssi_hist.append(r)
        if f.lqi is not None:
            self.lqi_last = f.lqi

    @property
    def rssi_avg(self):
        return self.rssi_sum / self.rssi_n if self.rssi_n else None

    def merge(self, o: "Device"):
        """Fold a placeholder (short-address-only) device into this one."""
        self.frames += o.frames
        self.counts.update(o.counts)
        self.first = min(x for x in (self.first, o.first) if x) if (self.first or o.first) else 0
        self.last = max(self.last, o.last)
        for r in o.rssi_hist:
            self.rssi_hist.append(r)
        if o.rssi_n:
            self.rssi_sum += o.rssi_sum
            self.rssi_n += o.rssi_n
            self.rssi_min = o.rssi_min if self.rssi_min is None else min(self.rssi_min, o.rssi_min)
            self.rssi_max = o.rssi_max if self.rssi_max is None else max(self.rssi_max, o.rssi_max)
            if self.rssi_last is None or o.last >= self.last:
                self.rssi_last = o.rssi_last
        for k, v in o.addresses.items():
            self.addresses.setdefault(k, v)
        self.thread = self.thread or o.thread
        if self.ping is None:
            self.ping = o.ping

    @property
    def name(self):
        return self.ext.hex() if self.ext else f"rloc 0x{self.rloc16:04x}"


def is_rloc_iid(iid: bytes) -> bool:
    return iid[:6] == lowpan.RLOC_IID_HEAD


class Store:
    def __init__(self, km: crypto.KeyManager | None, thread_pan=None, mesh_local_prefix=None,
                 network_name=None):
        self.km = km
        self.thread_pan = thread_pan
        self.mesh_local_prefix = mesh_local_prefix          # 8 bytes
        self.network_name = network_name
        self.contexts = {}
        if mesh_local_prefix:
            self.contexts[0] = mesh_local_prefix
        self.on_mesh = set()                                # /64 prefixes (8 bytes)
        self.netdata = None
        self.leader = None                                  # latest Leader Data seen
        self.devices: dict[str, Device] = {}
        self.short2key = {}                                 # (pan, short) -> device key
        self.stats = Stats()
        self.reasm = lowpan.Reassembler()
        self._ack = None                                    # (seq, dst key, time)
        self.log = collections.deque(maxlen=200)

    # ---- device lookup -------------------------------------------------------------------------
    def _by_ext(self, ext: bytes, pan, now) -> Device:
        k = ext.hex()
        d = self.devices.get(k)
        if d is None:
            d = self.devices[k] = Device(key=k, ext=ext, pan=pan, first=now)
        if pan is not None and d.pan is None:
            d.pan = pan
        return d

    def _by_short(self, short: int, pan, now) -> Device:
        k = self.short2key.get((pan, short))
        if k and k in self.devices:
            return self.devices[k]
        k = f"s:{pan if pan is not None else 0:04x}:{short:04x}"
        d = self.devices.get(k)
        if d is None:
            d = self.devices[k] = Device(key=k, rloc16=short, pan=pan, first=now)
            self.short2key[(pan, short)] = k
        return d

    def _dev(self, addr, pan, now):
        if addr is None:
            return None
        if isinstance(addr, bytes):
            return self._by_ext(addr, pan, now)
        if addr == wpan.BROADCAST:
            return None
        return self._by_short(addr, pan, now)

    def _ext_for_short(self, pan, short):
        k = self.short2key.get((pan, short))
        d = self.devices.get(k) if k else None
        return d.ext if d else None

    def map_short(self, pan, short, ext: bytes):
        """Learn that `short` (an RLOC16) currently belongs to `ext`."""
        if short is None or short >= 0xFFFE:
            return
        d = self._by_ext(ext, pan, 0)
        old_key = self.short2key.get((pan, short))
        if old_key == d.key and d.rloc16 == short:
            return
        if d.rloc16 is not None and d.rloc16 != short:
            self.short2key.pop((pan, d.rloc16), None)
        if old_key and old_key != d.key:
            old = self.devices.get(old_key)
            if old is not None and old.ext is None:        # placeholder: fold it in
                d.merge(old)
                if old.rloc16 is not None:
                    pass
                del self.devices[old_key]
            elif old is not None:                          # RLOC moved from another device
                old.rloc16 = None
        d.rloc16 = short
        self.short2key[(pan, short)] = d.key

    # ---- ingest ----------------------------------------------------------------------------------
    def ingest(self, rx: RxFrame):
        self.stats.frames += 1
        try:
            f = wpan.parse(rx.psdu)
        except wpan.ParseError:
            self.stats.bad += 1
            return
        now = rx.t
        if f.ftype == wpan.FT_ACK:
            self._handle_ack(f, rx)
            return
        pan = f.pan
        if f.ack_req and f.dst is not None and f.seq is not None:
            dd = self._dev(f.dst, pan, now)
            self._ack = (f.seq, dd.key if dd else None, now)

        plain = None
        src_ext = f.src if isinstance(f.src, bytes) else (
            self._ext_for_short(pan, f.src) if f.src is not None else None)
        decrypted = False
        if f.security:
            if self.km is not None and f.frame_counter is not None:
                plain, used = self._mac_decrypt(f, src_ext, pan)
                if plain is not None:
                    decrypted = True
                    if isinstance(f.src, int) and used is not None and used != src_ext:
                        self.map_short(pan, f.src, used)
            if plain is None:
                self.stats.undecryptable += 1
        else:
            plain = f.payload

        dev = self._dev(f.src, pan, now)
        if dev is None:
            return
        dev.rx(rx)
        dev.counts[wpan.FT_NAMES.get(f.ftype, str(f.ftype))] += 1
        if f.frame_counter is not None and decrypted:
            dev.mac_fc = f.frame_counter
        if decrypted:
            dev.thread = True
            self.stats.decrypted += 1
            if self.thread_pan is None and pan is not None:
                self.thread_pan = pan
        if pan is not None and self.thread_pan is not None and pan == self.thread_pan:
            self.stats.thread += 1
        elif not dev.thread:
            self.stats.foreign += 1

        if f.security and plain is None:
            dev.counts["undecrypted"] += 1
            dev.last_frame = f"{wpan.FT_NAMES.get(f.ftype, '?')} (encrypted)"
            return
        if plain is not None and f.payload_ies:
            plain = wpan.skip_payload_ies(plain)

        if f.ftype == wpan.FT_CMD and plain:
            name = wpan.CMD_NAMES.get(plain[0], f"cmd 0x{plain[0]:02x}")
            dev.last_frame = name
            if plain[0] == 4:
                dev.counts["poll"] += 1
            return
        if f.ftype == wpan.FT_BEACON:
            dev.last_frame = "Beacon"
            return
        if f.ftype != wpan.FT_DATA or not plain:
            return
        if pan is not None and self.thread_pan is not None and pan != self.thread_pan and not dev.thread:
            dev.last_frame = "data"
            return
        self._handle_lowpan(f, plain, dev, pan, now)

    def _handle_ack(self, f, rx):
        a = self._ack
        if a and f.seq == a[0] and rx.t - a[2] <= ACK_WINDOW and a[1] in self.devices:
            d = self.devices[a[1]]
            d.rx(rx)
            d.counts["ack"] += 1
            self._ack = None
        else:
            self.stats.acks_unmatched += 1

    def _mac_decrypt(self, f, src_ext, pan):
        if f.key_id_mode == 1 and f.key_index is not None:
            seq = self.km.seq_for_mac_index(f.key_index)
        elif f.key_id_mode == 2 and len(f.key_source) == 4:
            seq = int.from_bytes(f.key_source, "big")
        else:
            return None, None
        key = self.km.mac_key(seq)
        aad = f.raw[:f.hdr_len]
        cands = [src_ext] if src_ext else []
        if isinstance(f.src, int) or src_ext is None:
            # Unknown short source: try every known Thread device on this PAN (there are few).
            cands += [d.ext for d in self.devices.values()
                      if d.ext and d.ext != src_ext and (d.thread or d.pan == pan)]
        for ext in cands:
            p = crypto.ccm_decrypt(key, crypto.nonce(ext, f.frame_counter, f.sec_level), aad,
                                   f.payload, f.mic, encrypted=f.sec_level >= 4)
            if p is not None:
                return p, ext
        return None, None

    def _handle_lowpan(self, f, plain, dev, pan, now):
        try:
            lp = lowpan.decode(plain, f.src, f.dst, self.contexts, self.reasm, now)
        except (lowpan.LowpanError, IndexError, ValueError):
            dev.last_frame = "6LoWPAN (undecodable)"
            return
        origin = dev
        if lp.mesh_src is not None:
            o = self._dev(lp.mesh_src, pan, now)
            if o is not None:
                origin = o
                o.thread = o.thread or dev.thread
                if o is not dev:
                    o.last = max(o.last, now)
                    o.counts["via mesh"] += 1
        if lp.ipv6 is None:
            dev.last_frame = "6LoWPAN fragment"
            return
        pkt = lowpan.parse_ipv6(lp.ipv6)
        if pkt is None:
            return
        self._learn_address(origin, pkt.src)
        what = "IPv6"
        if pkt.proto == 17:
            what = f"UDP {pkt.sport}->{pkt.dport}"
            if pkt.sport == mle.MLE_PORT and pkt.dport == mle.MLE_PORT and self.km is not None:
                self._handle_mle(pkt, dev, pan, now)
                return
            svc = lowpan.UDP_PORTS.get(pkt.dport) or lowpan.UDP_PORTS.get(pkt.sport)
            if svc:
                what += f" ({svc})"
        elif pkt.proto == 58:
            what = "ICMPv6 " + lowpan.ICMP6_NAMES.get(pkt.icmp_type, str(pkt.icmp_type))
        elif pkt.proto == 41 and pkt.inner is not None:
            what = "IPv6-in-IPv6"
        origin.last_frame = f"{what}  {fmt_ip(pkt.src)} -> {fmt_ip(pkt.dst)}"
        if origin is not dev:
            dev.last_frame = f"forwarding for {origin.name}"

    def _learn_address(self, dev, a: bytes):
        if a[0] == 0xFF or a == bytes(16):
            return
        prefix, iid = a[:8], a[8:]
        if prefix == lowpan.UNKNOWN_PREFIX:
            return
        if prefix == LL_PREFIX:
            return                                   # derived from ext; shown separately
        is_ml = self.mesh_local_prefix is not None and prefix == self.mesh_local_prefix
        if is_rloc_iid(iid):
            if iid[6] == 0xFC:                       # ALOC
                return
            if self.mesh_local_prefix is None:
                self.mesh_local_prefix = prefix
                self.contexts.setdefault(0, prefix)
            return                                   # RLOC: shown from rloc16
        is_child = dev.rloc16 is not None and dev.rloc16 & 0x1FF
        if is_ml or prefix in self.on_mesh or is_child:
            if is_child and not is_ml:
                self.on_mesh.add(prefix)
            s = fmt_ip(a)
            dev.addresses.setdefault(s, "seen")

    def _handle_mle(self, pkt, dev, pan, now):
        m = mle.decrypt(pkt.payload, pkt.src, pkt.dst, self.km)
        if not m.ok:
            dev.counts["mle (undecrypted)"] += 1
            dev.last_frame = "MLE (could not decrypt)"
            return
        sender = dev
        if m.sender_ext and dev.ext != m.sender_ext:
            sender = self._by_ext(m.sender_ext, pan, now)
        sender.thread = True
        if m.key_seq is not None:
            self.km.observe_seq(m.key_seq)
            sender.key_seq = m.key_seq
        if m.frame_counter is not None:
            sender.mle_fc = m.frame_counter
        sender.mle_counts[m.name] += 1
        sender.mle_last = (m.name, now)
        sender.counts["mle"] += 1
        t = m.tlvs
        dst_ext = iid_to_ext(pkt.dst[8:]) if pkt.dst[:8] == LL_PREFIX else None
        sender.last_frame = f"MLE {m.name}" + (f" -> {dst_ext.hex()}" if dst_ext else " (multicast)")
        if mle.T_SOURCE in t and isinstance(t[mle.T_SOURCE], int) and sender.ext:
            self.map_short(pan, t[mle.T_SOURCE], sender.ext)
        if mle.T_MODE in t and isinstance(t[mle.T_MODE], int):
            sender.mode = t[mle.T_MODE]
        if mle.T_TIMEOUT in t and isinstance(t[mle.T_TIMEOUT], int):
            sender.timeout = t[mle.T_TIMEOUT]
        if mle.T_VERSION in t and isinstance(t[mle.T_VERSION], int):
            sender.version = t[mle.T_VERSION]
        if mle.T_LINK_MARGIN in t and isinstance(t[mle.T_LINK_MARGIN], int):
            sender.link_margin = t[mle.T_LINK_MARGIN]
        if isinstance(t.get(mle.T_LEADER), dict):
            sender.leader = t[mle.T_LEADER]
            self.leader = t[mle.T_LEADER]
        if isinstance(t.get(mle.T_ROUTE64), dict):
            sender.route = t[mle.T_ROUTE64]
        if isinstance(t.get(mle.T_CONNECTIVITY), dict):
            sender.connectivity = t[mle.T_CONNECTIVITY]
        if mle.T_ADDR16 in t and isinstance(t[mle.T_ADDR16], int) and dst_ext:
            self.map_short(pan, t[mle.T_ADDR16], dst_ext)      # Child ID Response: child's RLOC16
        if isinstance(t.get(mle.T_NETDATA), dict):
            nd = t[mle.T_NETDATA]
            self.netdata = nd
            self.contexts.update(nd["contexts"])
            for p in nd["prefixes"]:
                if p["len"] == 64 and any(br["on_mesh"] for br in p["border_routers"]):
                    self.on_mesh.add(p["prefix"][:8])
        for k in (mle.T_ACTIVE_DS, mle.T_PENDING_DS):
            ds = t.get(k)
            if isinstance(ds, dict):
                if ds.get("mesh_local_prefix") and self.mesh_local_prefix is None:
                    self.mesh_local_prefix = ds["mesh_local_prefix"]
                    self.contexts.setdefault(0, self.mesh_local_prefix)
                if ds.get("network_name") and not self.network_name:
                    self.network_name = ds["network_name"]
        if isinstance(t.get(mle.T_ADDR_REG), list):
            for kind, cid, data in t[mle.T_ADDR_REG]:
                if kind == "full":
                    a = data
                else:
                    p = self.contexts.get(cid)
                    if p is None:
                        continue
                    a = p + data
                    if cid != 0:
                        self.on_mesh.add(p)
                if a[:8] != LL_PREFIX and not is_rloc_iid(a[8:]):
                    sender.addresses[fmt_ip(a)] = "registered"

    # ---- derived views -----------------------------------------------------------------------
    def role(self, d: Device) -> str:
        r = d.rloc16
        if self.thread_pan is not None and d.pan is not None and d.pan != self.thread_pan and not d.thread:
            return "other pan"
        if r is None:
            if d.mle_counts.get("Parent Request") or d.mle_counts.get("Child ID Request"):
                return "attaching"
            return "?" if d.thread else ""
        if r & 0x1FF:
            if d.mode is not None:
                return "child" if d.mode & 0x08 else "sleepy child"
            return "sleepy child" if d.counts.get("poll") or d.counts.get("cmd") else "child"
        if self.leader and self.leader.get("leader_router_id") == r >> 10:
            return "leader"
        return "router"

    def parent_of(self, d: Device):
        if d.rloc16 is None or not d.rloc16 & 0x1FF:
            return None
        k = self.short2key.get((d.pan, d.rloc16 & 0xFC00))
        return self.devices.get(k) if k else None

    def children_of(self, d: Device):
        if d.rloc16 is None or d.rloc16 & 0x1FF:
            return []
        return sorted((c for c in self.devices.values()
                       if c is not d and c.rloc16 is not None and c.rloc16 & 0xFC00 == d.rloc16
                       and c.rloc16 & 0x1FF and c.pan == d.pan), key=lambda c: c.rloc16)

    def addresses(self, d: Device):
        """[(address, kind)] best ping target first."""
        out = []
        for a, origin in d.addresses.items():
            ip = ipaddress.IPv6Address(a)
            prefix = ip.packed[:8]
            if self.mesh_local_prefix and prefix == self.mesh_local_prefix:
                kind = "ML-EID"
            elif ip.is_global:
                kind = "global"
            else:
                kind = "OMR" if prefix in self.on_mesh or origin == "registered" else "ULA"
            out.append((a, kind, origin))
        if d.rloc16 is not None and self.mesh_local_prefix:
            out.append((fmt_ip(self.mesh_local_prefix + lowpan.RLOC_IID_HEAD +
                               d.rloc16.to_bytes(2, "big")), "RLOC", "derived"))
        if d.ext:
            out.append((fmt_ip(LL_PREFIX + lowpan.mac_iid(d.ext)), "link-local", "derived"))
        rank = {"OMR": 0, "global": 1, "ULA": 2, "ML-EID": 3, "RLOC": 4, "link-local": 5}
        out.sort(key=lambda x: rank.get(x[1], 9))
        return out
