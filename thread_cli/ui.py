"""curses UI, modelled on mdns-cli: fold devices open, pick values with left/right, c copies, p pings."""
import curses
import ipaddress
import time

from . import clip, mle
from .config import Config
from .ping import Ping

SPARK = "▁▂▃▄▅▆▇█"
SORTS = ["rloc", "rssi", "last seen", "frames", "name"]
STALE = 120.0
HELP = [
    ("↑ ↓ / k j", "move"),
    ("PgUp PgDn, Home End / g G", "page, first, last"),
    ("Enter, Space", "fold open or closed"),
    ("→ / l", "fold open, then step through the values on the row"),
    ("← / h", "step back, then fold closed or jump to the parent"),
    ("e / E", "expand all / collapse all"),
    ("p", "ping the device (or the picked address); again to stop"),
    ("c", "copy the value under the cursor"),
    ("N", "name the device (saved by ext address; empty name removes it)"),
    ("s", "cycle sort: " + ", ".join(SORTS)),
    ("/", "filter (ext, rloc16, role, addresses, last frame)"),
    ("a", "show / hide devices from other PANs (Zigbee etc.)"),
    ("[ ]", "previous / next channel"),
    ("Esc", "clear the filter, then quit"),
    ("?", "this help"),
    ("q", "quit"),
]


def ago(t, now):
    if not t:
        return "-"
    s = max(0, now - t)
    if s < 60:
        return f"{s:.0f}s"
    if s < 3600:
        return f"{s / 60:.0f}m"
    return f"{s / 3600:.1f}h"


def hms(t):
    return time.strftime("%H:%M:%S", time.localtime(t)) if t else "-"


def spark(vals, width=12):
    vals = list(vals)[-width:]
    out = ""
    for v in vals:
        i = int((v + 105) / 60 * (len(SPARK) - 1) + 0.5)
        out += SPARK[max(0, min(len(SPARK) - 1, i))]
    return out


def mode_str(m):
    if m is None:
        return None
    parts = ["rx-on-when-idle" if m & 0x08 else "rx-off-when-idle (sleepy)",
             "FTD" if m & 0x02 else "MTD",
             "full network data" if m & 0x01 else "stable network data"]
    return ", ".join(parts) + f"  (0x{m:02x})"


class Colors:
    def __init__(self):
        self.ok = curses.has_colors()
        self.sel_bg = None
        self.pairs = {}
        if not self.ok:
            return
        curses.start_color()
        try:
            curses.use_default_colors()
            bg = -1
        except curses.error:
            bg = curses.COLOR_BLACK
        fgs = {"cyan": curses.COLOR_CYAN, "green": curses.COLOR_GREEN, "yellow": curses.COLOR_YELLOW,
               "red": curses.COLOR_RED, "magenta": curses.COLOR_MAGENTA, "blue": curses.COLOR_BLUE,
               "white": curses.COLOR_WHITE, "default": -1 if bg == -1 else curses.COLOR_WHITE}
        amber = 214 if curses.COLORS >= 256 else curses.COLOR_YELLOW
        fgs["amber"] = amber
        grey = 8 if curses.COLORS >= 16 else curses.COLOR_WHITE
        fgs["grey"] = grey
        self.sel_bg = 236 if curses.COLORS >= 256 else None
        n = 1
        for name, fg in fgs.items():
            curses.init_pair(n, fg, bg)
            self.pairs[(name, False)] = curses.color_pair(n)
            n += 1
            if self.sel_bg is not None:
                curses.init_pair(n, fg, self.sel_bg)
                self.pairs[(name, True)] = curses.color_pair(n)
                n += 1

    def __call__(self, name, sel=False, extra=0):
        if not self.ok:
            base = 0
            if name in ("grey",):
                base = curses.A_DIM
            return base | extra | (curses.A_REVERSE if sel else 0)
        a = self.pairs.get((name, sel and self.sel_bg is not None), 0)
        if sel and self.sel_bg is None:
            a |= curses.A_REVERSE
        if name == "grey" and curses.COLORS < 16:
            a |= curses.A_DIM
        return a | extra


def rssi_color(r):
    if r is None:
        return "grey"
    return "green" if r >= -70 else "yellow" if r >= -85 else "red"


ROLE_COLORS = {"leader": "magenta", "router": "green", "child": "cyan", "sleepy child": "cyan",
               "attaching": "amber", "?": "grey", "": "grey"}
PING_COLORS = {"good": "green", "warn": "yellow", "bad": "red"}


class Row:
    __slots__ = ("dev", "id", "segs", "values", "is_dev", "addr")

    def __init__(self, dev, rid, is_dev=False):
        self.dev, self.id, self.is_dev = dev, rid, is_dev
        self.segs = []       # (text, color name, extra attr, value index or None)
        self.values = []     # strings that can be picked / copied
        self.addr = None     # default ping target for this row

    def add(self, text, color="default", extra=0, value=None):
        vi = None
        if value is not None:
            vi = len(self.values)
            self.values.append(value)
        self.segs.append((text, color, extra, vi))
        return self


class UI:
    def __init__(self, scr, cap, args):
        self.scr, self.cap, self.args = scr, cap, args
        self.store = cap.store
        self.c = Colors()
        self.expanded = set()
        self.cursor = (None, None)    # (device key, row id)
        self.pick = None              # value index on the cursor row
        self.top = 0
        self.sort = 0
        self.filter = ""
        self.filtering = False
        self.show_foreign = False
        self.help = False
        self.msg = ""
        self.msg_t = 0
        self.rows = []
        self.config = getattr(args, "config", None) or Config()
        self.naming = None            # (device key, text being typed) while the N prompt is open
        if self.config.error:
            self.flash(f"config: {self.config.error}")

    def label(self, d):
        return self.config.name(d.ext)

    # ---- model -> rows -------------------------------------------------------------------------
    def visible_devices(self):
        st = self.store
        out = []
        for d in st.devices.values():
            if not self.show_foreign and not d.thread and (st.thread_pan is None or d.pan != st.thread_pan):
                continue
            if self.filter and not self._matches(d):
                continue
            out.append(d)
        key = SORTS[self.sort]
        if key == "rloc":
            out.sort(key=lambda d: (not d.thread, d.rloc16 if d.rloc16 is not None else 0x10000, d.key))
        elif key == "rssi":
            out.sort(key=lambda d: -(d.rssi_avg if d.rssi_avg is not None else -999))
        elif key == "last seen":
            out.sort(key=lambda d: -d.last)
        elif key == "frames":
            out.sort(key=lambda d: -d.frames)
        else:
            out.sort(key=lambda d: (not self.label(d), self.label(d).lower(), d.name))
        return out

    def _matches(self, d):
        f = self.filter.lower()
        hay = [d.name, self.label(d), f"0x{d.rloc16:04x}" if d.rloc16 is not None else "", self.store.role(d),
               d.last_frame] + list(d.addresses)
        return any(f in h.lower() for h in hay)

    def build(self, now):
        rows = []
        devs = self.visible_devices()
        self.name_w = min(24, max([len(self.label(d)) for d in devs] + [0]))
        for d in devs:
            rows.append(self.dev_row(d, now))
            if d.key in self.expanded:
                rows += self.detail_rows(d, now)
        self.rows = rows

    def dev_row(self, d, now):
        st = self.store
        r = Row(d.key, "dev", is_dev=True)
        r.add("▾ " if d.key in self.expanded else "▸ ", "grey")
        stale = now - d.last > STALE
        if d.ext:
            r.add(f"{d.ext.hex():<16}", "amber" if stale else ("white" if d.thread else "grey"),
                  curses.A_BOLD if d.thread and not stale else 0, value=d.ext.hex())
        else:
            r.add(f"{'(ext unknown)':<16}", "grey")
        if self.name_w:
            nm = self.label(d)
            r.add("  ")
            r.add(f"{nm[:self.name_w]:<{self.name_w}}", "white", curses.A_BOLD, value=nm or None)
        r.add("  ")
        if d.rloc16 is not None:
            r.add(f"0x{d.rloc16:04x}", "cyan", value=f"0x{d.rloc16:04x}")
        else:
            r.add("      ")
        role = st.role(d)
        if not d.thread and (st.thread_pan is None or d.pan != st.thread_pan):
            role = f"PAN 0x{d.pan:04x}" if d.pan is not None else "foreign"
            rc = "grey"
        else:
            rc = ROLE_COLORS.get(role, "default")
        r.add(f"  {role:<13}", rc)
        rs = f"{d.rssi_last:>4} dBm" if d.rssi_last is not None else "    -   "
        r.add(rs, rssi_color(d.rssi_last))
        r.add(" " + f"{spark(d.rssi_hist):<12}", rssi_color(d.rssi_avg))
        r.add(f"  {d.frames:>5} fr", "default")
        r.add(f"  {ago(d.last, now):>4}", "amber" if stale else "grey")
        if d.ping:
            p = d.ping
            if p.received:
                txt = f"  ping {p.last:.1f}ms {p.loss:.0f}%"
            elif p.error:
                txt = f"  ping: {p.error}"
            else:
                txt = f"  ping {p.sent} sent"
            r.add(txt, PING_COLORS[p.grade()], 0 if p.running else curses.A_DIM)
        addrs = st.addresses(d)
        r.addr = addrs[0][0] if addrs else None
        return r

    def add_name(self, r, d):
        nm = self.label(d)
        if nm:
            r.add("  ").add(nm, "white", curses.A_BOLD, value=nm)

    def kv(self, d, rid, key, value=None, color="default", pick=None):
        r = Row(d.key, rid)
        r.add("      ")
        r.add(f"{key:<14}", "blue")
        if value is not None:
            r.add(str(value), color, value=pick)
        return r

    def detail_rows(self, d, now):
        st = self.store
        rows = []
        if self.label(d):
            rows.append(self.kv(d, "name", "name", self.label(d), "white", self.label(d)))
        role = st.role(d)
        r = self.kv(d, "role", "role", role or "-", ROLE_COLORS.get(role, "default"))
        par = st.parent_of(d)
        if par:
            r.add(", parent ", "default").add(f"0x{par.rloc16:04x}", "cyan", value=f"0x{par.rloc16:04x}")
            if par.ext:
                r.add(" (").add(par.ext.hex(), "white", value=par.ext.hex()).add(")")
            self.add_name(r, par)
        rows.append(r)
        if d.ext:
            rows.append(self.kv(d, "ext", "ext address", d.ext.hex(), "white", d.ext.hex()))
        else:
            rows.append(self.kv(d, "ext", "ext address",
                                "unknown until it sends an MLE message; its frames can't be decrypted yet",
                                "amber"))
        if d.rloc16 is not None:
            r = self.kv(d, "rloc", "rloc16", f"0x{d.rloc16:04x}", "cyan", f"0x{d.rloc16:04x}")
            cid = d.rloc16 & 0x1FF
            r.add(f"  router id {d.rloc16 >> 10}" + (f", child id {cid}" if cid else ""), "grey")
            rows.append(r)
        ms = mode_str(d.mode)
        if ms:
            rows.append(self.kv(d, "mode", "mode", ms))
        if d.rssi_n:
            r = self.kv(d, "rssi", "rssi")
            r.add("last ").add(f"{d.rssi_last}", rssi_color(d.rssi_last), value=str(d.rssi_last))
            r.add("  avg ").add(f"{d.rssi_avg:.1f}", rssi_color(d.rssi_avg), value=f"{d.rssi_avg:.1f}")
            r.add("  min ").add(f"{d.rssi_min}", rssi_color(d.rssi_min))
            r.add("  max ").add(f"{d.rssi_max}", rssi_color(d.rssi_max))
            r.add(f"  dBm over {d.rssi_n} frames  ", "grey").add(spark(d.rssi_hist, 24), rssi_color(d.rssi_avg))
            rows.append(r)
        if d.lqi_last is not None or d.link_margin is not None:
            parts = []
            if d.lqi_last is not None:
                parts.append(f"lqi {d.lqi_last}")
            if d.link_margin is not None:
                parts.append(f"reported link margin {d.link_margin} dB")
            rows.append(self.kv(d, "lqi", "link", ", ".join(parts)))
        r = self.kv(d, "seen", "seen", f"first {hms(d.first)}, last {hms(d.last)} ({ago(d.last, now)} ago)",
                    "amber" if now - d.last > STALE else "default")
        if d.channel:
            r.add(f"  ch {d.channel}", "grey")
        if d.pan is not None:
            r.add(f"  PAN 0x{d.pan:04x}", "grey")
        rows.append(r)
        if d.counts:
            order = ["data", "mle", "poll", "cmd", "ack", "beacon", "via mesh", "undecrypted",
                     "mle (undecrypted)"]
            items = sorted(d.counts.items(), key=lambda kv: order.index(kv[0]) if kv[0] in order else 99)
            rows.append(self.kv(d, "frames", "frames", ", ".join(f"{k} {v}" for k, v in items)))
        if d.last_frame:
            rows.append(self.kv(d, "lastf", "last frame", d.last_frame, "default", d.last_frame))
        if d.mle_counts:
            txt = ", ".join(f"{k} ×{v}" for k, v in d.mle_counts.most_common())
            if d.mle_last:
                txt += f"; last {d.mle_last[0]} {ago(d.mle_last[1], now)} ago"
            rows.append(self.kv(d, "mle", "mle", txt))
        if d.version is not None:
            rows.append(self.kv(d, "ver", "version",
                                f"Thread {mle.THREAD_VERSIONS.get(d.version, '?')} ({d.version})"))
        if d.timeout is not None:
            rows.append(self.kv(d, "tmo", "timeout", f"{d.timeout} s"))
        if d.leader:
            L = d.leader
            rows.append(self.kv(d, "leader", "leader data",
                                f"partition 0x{L['partition']:08x}, weighting {L['weighting']}, data version "
                                f"{L['data_version']}/{L['stable_data_version']}, leader router "
                                f"{L['leader_router_id']}"))
        if d.route:
            own = d.rloc16 >> 10 if d.rloc16 is not None else None
            for i, rt in enumerate(d.route["routes"]):
                rid = rt["router_id"]
                peer = st.devices.get(st.short2key.get((d.pan, rid << 10), ""))
                key = "routes" if i == 0 else ""
                r = self.kv(d, f"route{rid}", key)
                r.add(f"router {rid:<2} ").add(f"0x{rid << 10:04x}", "cyan", value=f"0x{rid << 10:04x}")
                if rid == own:
                    r.add("  (self)", "grey")
                else:
                    lq = lambda v: "green" if v == 3 else "yellow" if v == 2 else "red"
                    r.add("  lq in ").add(str(rt["lq_in"]), lq(rt["lq_in"]))
                    r.add(" out ").add(str(rt["lq_out"]), lq(rt["lq_out"]))
                    r.add(f"  cost {rt['cost'] or '∞'}")
                if peer and peer.ext:
                    r.add("  ").add(peer.ext.hex(), "white", value=peer.ext.hex())
                    self.add_name(r, peer)
                rows.append(r)
        if d.connectivity:
            c = d.connectivity
            txt = (f"parent priority {c['parent_priority']}, links lq3/2/1 {c['lq3']}/{c['lq2']}/{c['lq1']}, "
                   f"leader cost {c['leader_cost']}, active routers {c['active_routers']}")
            rows.append(self.kv(d, "conn", "connectivity", txt))
        for i, ch in enumerate(st.children_of(d)):
            r = self.kv(d, f"child{ch.key}", "children" if i == 0 else "")
            r.add(f"0x{ch.rloc16:04x}", "cyan", value=f"0x{ch.rloc16:04x}")
            r.add(f"  {st.role(ch):<13}", ROLE_COLORS.get(st.role(ch), "default"))
            if ch.ext:
                r.add(" ").add(ch.ext.hex(), "white", value=ch.ext.hex())
                self.add_name(r, ch)
            if ch.rssi_last is not None:
                r.add(f"  {ch.rssi_last} dBm", rssi_color(ch.rssi_last))
            rows.append(r)
        for i, (a, kind, origin) in enumerate(st.addresses(d)):
            r = self.kv(d, f"addr{a}", "addresses" if i == 0 else "")
            r.add(a, "cyan", value=a)
            r.add(f"  {kind}" + (f" ({origin})" if origin not in ("derived", "seen") else ""), "grey")
            if kind in ("ML-EID", "RLOC", "link-local"):
                r.add("  not routed off-mesh", "grey", curses.A_DIM)
            r.addr = a
            rows.append(r)
        fcs = []
        if d.mac_fc is not None:
            fcs.append(f"mac {d.mac_fc}")
        if d.mle_fc is not None:
            fcs.append(f"mle {d.mle_fc}")
        if d.key_seq is not None:
            fcs.append(f"key seq {d.key_seq}")
        if fcs:
            rows.append(self.kv(d, "fc", "frame ctrs", ", ".join(fcs)))
        if d.ping:
            p = d.ping
            r = self.kv(d, "ping", "ping")
            r.add(p.addr, "cyan", value=p.addr)
            r.add(f"  {p.sent} sent, {p.received} received, {p.loss:.0f}% loss",
                  PING_COLORS[p.grade()])
            r.add("  (running, p to stop)" if p.running else "  (stopped)", "grey")
            r.addr = p.addr
            rows.append(r)
            if p.error:
                rows.append(self.kv(d, "pingerr", "", p.error, "red"))
            if p.received:
                rows.append(self.kv(d, "rtt", "rtt", f"last {p.last:.2f} ms, min {p.min:.2f}, "
                                                      f"avg {p.avg:.2f}, max {p.max:.2f}",
                                    PING_COLORS[p.grade()]))
        for r in rows:
            if r.addr is None:
                r.addr = None
        return rows

    # ---- drawing --------------------------------------------------------------------------------
    def put(self, y, x, text, attr=0):
        h, w = self.scr.getmaxyx()
        if y >= h or x >= w:
            return x
        text = text[:max(0, w - x - (1 if y == h - 1 else 0))]
        try:
            self.scr.addstr(y, x, text, attr)
        except curses.error:
            pass
        return x + len(text)

    def draw(self, now):
        self.build(now)
        scr = self.scr
        scr.erase()
        h, w = scr.getmaxyx()
        st, cap = self.store, self.cap
        nthread = sum(1 for d in st.devices.values() if d.thread)
        x = self.put(0, 0, "thread-cli", self.c("white", extra=curses.A_BOLD))
        x = self.put(0, x, f"  {nthread} thread devices", self.c("default"))
        if self.show_foreign:
            x = self.put(0, x, f" ({len(st.devices)} total)", self.c("grey"))
        x = self.put(0, x, f"  ch {cap.channel}", self.c("yellow"))
        if st.thread_pan is not None:
            x = self.put(0, x, f"  PAN 0x{st.thread_pan:04x}", self.c("default"))
        if st.network_name:
            x = self.put(0, x, f"  {st.network_name}", self.c("white", extra=curses.A_BOLD))
        s = st.stats
        x = self.put(0, x, f"  {s.frames} frames, {s.decrypted} decrypted", self.c("grey"))
        x = self.put(0, x, f"  sort:{SORTS[self.sort]}", self.c("grey"))
        if self.filter or self.filtering:
            x = self.put(0, x, f"  /{self.filter}" + ("▏" if self.filtering else ""), self.c("yellow"))
        err = cap.error
        tail = f"error: {err}" if err else (
            "key: none" if st.km is None else f"key seq {st.km.seq}")
        self.put(0, max(x + 2, w - len(tail) - 1), tail, self.c("red" if err or st.km is None else "grey"))
        line2 = []
        if st.leader:
            line2.append(f"leader router {st.leader['leader_router_id']}, "
                         f"partition 0x{st.leader['partition']:08x}")
        if st.mesh_local_prefix:
            line2.append("mesh-local " + str(ipaddress.IPv6Address(st.mesh_local_prefix + bytes(8))) + "/64")
        if st.on_mesh:
            line2.append("OMR " + ", ".join(str(ipaddress.IPv6Address(p + bytes(8))) + "/64"
                                             for p in sorted(st.on_mesh)))
        self.put(1, 0, "  ".join(line2) or "waiting for MLE traffic…", self.c("grey"))
        self.put(2, 0, "─" * w, self.c("grey"))

        body_top, body_h = 3, h - 4
        idx = self._cursor_index()
        if idx is not None:
            if idx < self.top:
                self.top = idx
            elif idx >= self.top + body_h:
                self.top = idx - body_h + 1
        self.top = max(0, min(self.top, max(0, len(self.rows) - body_h)))
        for i, row in enumerate(self.rows[self.top:self.top + body_h]):
            y = body_top + i
            sel = (self.top + i) == idx
            if sel and self.c.sel_bg is not None:
                self.put(y, 0, " " * (w - 1), self.c("default", True))
            x = 0
            for text, color, extra, vi in row.segs:
                a = self.c(color, sel, extra)
                if sel and vi is not None and vi == self.pick:
                    a |= curses.A_UNDERLINE
                x = self.put(y, x, text, a)
        if not self.rows:
            msg = ("no Thread devices heard yet" if not st.devices else
                   "no matches" if self.filter else "only devices from other PANs so far (a to show)")
            self.put(body_top + 1, 4, msg, self.c("grey"))

        if self.naming:
            dev = self.store.devices.get(self.naming[0])
            x = self.put(h - 1, 0, f"name {dev.ext.hex() if dev and dev.ext else ''}: ", self.c("yellow"))
            self.put(h - 1, x, self.naming[1] + "▏", self.c("white", extra=curses.A_BOLD))
        elif self.msg and now - self.msg_t < 4:
            self.put(h - 1, 0, self.msg, self.c("yellow"))
        else:
            self.put(h - 1, 0, "Enter fold  ←→ pick  c copy  p ping  N name  s sort  / filter  a all PANs  "
                               "[ ] channel  ? help  q quit", self.c("grey"))
        scr.noutrefresh()
        if self.help:
            self.draw_help()
        curses.doupdate()

    def draw_help(self):
        h, w = self.scr.getmaxyx()
        bw = min(w - 4, 90)
        bh = min(h - 2, len(HELP) + 4)
        y0, x0 = max(0, (h - bh) // 2), max(0, (w - bw) // 2)
        win = curses.newwin(bh, bw, y0, x0)
        win.erase()
        win.border()
        win.addnstr(0, 2, " keys ", bw - 4, curses.A_BOLD)
        for i, (k, v) in enumerate(HELP[:bh - 4]):
            win.addnstr(2 + i, 2, f"{k:<26}", bw - 4, self.c("blue"))
            win.addnstr(2 + i, 29, v, max(0, bw - 31))
        win.noutrefresh()

    # ---- cursor -----------------------------------------------------------------------------------
    def _cursor_index(self):
        if not self.rows:
            return None
        key, rid = self.cursor
        for i, r in enumerate(self.rows):
            if r.dev == key and r.id == rid:
                return i
        for i, r in enumerate(self.rows):         # row vanished: fall back to its device
            if r.dev == key and r.is_dev:
                self.cursor = (r.dev, r.id)
                return i
        self.cursor = (self.rows[0].dev, self.rows[0].id)
        self.pick = None
        return 0

    def _move_to(self, i):
        if not self.rows:
            return
        i = max(0, min(len(self.rows) - 1, i))
        r = self.rows[i]
        if (r.dev, r.id) != self.cursor:
            self.pick = None
        self.cursor = (r.dev, r.id)

    def cur_row(self):
        i = self._cursor_index()
        return self.rows[i] if i is not None else None

    def flash(self, msg):
        self.msg, self.msg_t = msg, time.time()

    # ---- actions ----------------------------------------------------------------------------------
    def toggle(self, key, state=None):
        if state is None:
            state = key not in self.expanded
        if state:
            self.expanded.add(key)
        else:
            self.expanded.discard(key)

    def do_ping(self):
        row = self.cur_row()
        if row is None:
            return
        d = self.store.devices.get(row.dev)
        if d is None:
            return
        target = None
        if self.pick is not None and self.pick < len(row.values):
            v = row.values[self.pick]
            try:
                ipaddress.IPv6Address(v)
                target = v
            except ValueError:
                pass
        if target is None and not row.is_dev:
            target = row.addr
        if target is None:
            addrs = self.store.addresses(d)
            target = addrs[0][0] if addrs else None
        if d.ping and d.ping.running and (target is None or target == d.ping.addr):
            d.ping.stop()
            self.flash(f"ping {d.ping.addr} stopped")
            return
        if target is None:
            self.flash("no address known for this device yet")
            return
        if d.ping:
            d.ping.close()
        d.ping = Ping(target)
        kind = next((k for a, k, _ in self.store.addresses(d) if a == target), "")
        note = "  (mesh-local: only reachable from inside the mesh)" if kind in ("ML-EID", "RLOC", "link-local") else ""
        self.flash(f"pinging {target}{note}")

    def do_copy(self):
        row = self.cur_row()
        if row is None:
            return
        if self.pick is not None and self.pick < len(row.values):
            v = row.values[self.pick]
        elif row.values:
            v = row.values[0]
        else:
            v = "".join(s[0] for s in row.segs).strip()
        how = clip.copy(v)
        self.flash(f"copied {v}  via {how}")

    def key(self, ch):
        if self.help:
            self.help = False
            return True
        if self.naming:
            key, text = self.naming
            if ch in (10, 13, curses.KEY_ENTER):
                self.naming = None
                d = self.store.devices.get(key)
                if d and d.ext:
                    try:
                        self.config.set_name(d.ext, text)
                        self.flash(f"named {d.ext.hex()} {text.strip()!r}" if text.strip()
                                   else f"removed the name of {d.ext.hex()}")
                    except OSError as e:
                        self.flash(f"can't save the name: {e}")
            elif ch == 27:
                self.naming = None
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                self.naming = (key, text[:-1])
            elif ch == 21:                               # Ctrl-U clears
                self.naming = (key, "")
            elif isinstance(ch, str):
                self.naming = (key, text + ch)
            return True
        if self.filtering:
            if ch in (10, 13, curses.KEY_ENTER):
                self.filtering = False
            elif ch == 27:
                self.filtering, self.filter = False, ""
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                self.filter = self.filter[:-1]
            elif isinstance(ch, int) and 32 <= ch < 127:
                self.filter += chr(ch)
            return True
        i = self._cursor_index() or 0
        row = self.cur_row()
        h = self.scr.getmaxyx()[0] - 4
        if ch in (ord("q"),):
            return False
        if ch == 27:
            if self.filter:
                self.filter = ""
                return True
            return False
        if ch in (curses.KEY_UP, ord("k")):
            self._move_to(i - 1)
        elif ch in (curses.KEY_DOWN, ord("j")):
            self._move_to(i + 1)
        elif ch == curses.KEY_PPAGE:
            self._move_to(i - h)
        elif ch == curses.KEY_NPAGE:
            self._move_to(i + h)
        elif ch in (curses.KEY_HOME, ord("g")):
            self._move_to(0)
        elif ch in (curses.KEY_END, ord("G")):
            self._move_to(len(self.rows) - 1)
        elif ch in (10, 13, curses.KEY_ENTER, ord(" ")) and row:
            self.toggle(row.dev)
            self.cursor = (row.dev, "dev")
            self.pick = None
        elif ch in (curses.KEY_RIGHT, ord("l")) and row:
            if row.is_dev and row.dev not in self.expanded:
                self.toggle(row.dev, True)
            elif row.values:
                self.pick = 0 if self.pick is None else min(self.pick + 1, len(row.values) - 1)
        elif ch in (curses.KEY_LEFT, ord("h")) and row:
            if self.pick:
                self.pick -= 1
            elif self.pick == 0:
                self.pick = None
            elif row.is_dev:
                self.toggle(row.dev, False)
            else:
                self.cursor = (row.dev, "dev")
        elif ch == ord("e"):
            self.expanded = {d.key for d in self.visible_devices()}
        elif ch == ord("E"):
            self.expanded.clear()
            if row:
                self.cursor = (row.dev, "dev")
        elif ch == ord("p"):
            self.do_ping()
        elif ch == ord("c"):
            self.do_copy()
        elif ch == ord("N") and row:
            d = self.store.devices.get(row.dev)
            if d is None or d.ext is None:
                self.flash("can't name it yet: its ext address is unknown (RLOC16s change on reattach)")
            else:
                self.naming = (d.key, self.label(d))
        elif ch == ord("s"):
            self.sort = (self.sort + 1) % len(SORTS)
            self.flash(f"sort: {SORTS[self.sort]}")
        elif ch == ord("/"):
            self.filtering = True
        elif ch == ord("a"):
            self.show_foreign = not self.show_foreign
            self.flash("showing all PANs" if self.show_foreign else "showing only the Thread network")
        elif ch in (ord("["), ord("]")):
            if self.args.replay:
                self.flash("channel can't be changed while replaying")
            else:
                ch_new = self.cap.channel + (1 if ch == ord("]") else -1)
                ch_new = 11 + (ch_new - 11) % 16
                self.cap.set_channel(ch_new)
                self.flash(f"channel {ch_new}")
        elif ch == ord("?"):
            self.help = True
        return True

    def run(self):
        curses.curs_set(0)
        self.scr.keypad(True)
        self.scr.timeout(100)
        try:
            curses.set_escdelay(25)
        except AttributeError:
            pass
        end = time.time() + self.args.timeout if self.args.timeout else None
        last_draw = 0
        while True:
            self.cap.drain()
            now = time.time()
            for d in list(self.store.devices.values()):
                if d.ping:
                    d.ping.tick(now)
            if now - last_draw >= 0.25:
                self.draw(now)
                last_draw = now
            try:
                ch = self.scr.get_wch()
            except curses.error:
                ch = -1
            if isinstance(ch, str) and not (self.naming and ch.isprintable()):
                ch = ord(ch)
            if ch == curses.KEY_RESIZE:
                last_draw = 0
                continue
            if ch != -1:
                if not self.key(ch):
                    break
                self.draw(time.time())
                last_draw = time.time()
            if end and time.time() > end:
                break
        for d in self.store.devices.values():
            if d.ping:
                d.ping.close()
        return 0


def run_ui(cap, args):
    import locale
    locale.setlocale(locale.LC_ALL, "")
    return curses.wrapper(lambda scr: UI(scr, cap, args).run())
