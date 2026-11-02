"""thread-cli: interactive Thread network sniffer for an OpenThread RCP (spinel) radio."""
import argparse
import glob
import json
import os
import queue
import sys
import time

from . import crypto, pcap
from .config import Config, DeviceMemory, default_key_file
from .dataset import parse_dataset
from .store import Store

__version__ = "0.1.0"


def _hex(s: str) -> bytes:
    s = s.strip().lower().replace(":", "").replace(" ", "")
    if s.startswith("0x"):
        s = s[2:]
    return bytes.fromhex(s)


def find_port():
    ports = sorted(glob.glob("/dev/serial/by-id/usb-Espressif_USB_JTAG*"))
    if len(ports) == 1:
        return ports[0]
    if not ports:
        sys.exit("no Espressif USB-JTAG serial device found; pass --port")
    sys.exit("several Espressif devices found, pick one with --port:\n  " + "\n  ".join(ports))


def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        prog="thread-cli",
        description="Interactive Thread (802.15.4) sniffer: lists devices with RSSI, role and addresses, "
                    "decrypting with the network key. Talks spinel to an OpenThread RCP.")
    ap.add_argument("-k", "--key", help="Thread network key (32 hex digits)")
    ap.add_argument("--key-file", help="file holding the network key (default: ~/.config/thread-cli/networkkey "
                                       "or ~/.config/thread-logger/networkkey, if present)")
    ap.add_argument("-d", "--dataset", help="active operational dataset TLVs in hex (gives key, channel, "
                                            "PAN, mesh-local prefix and name)")
    ap.add_argument("-c", "--channel", type=int, help="802.15.4 channel 11-26 (default: dataset, config, else 11)")
    ap.add_argument("-u", "--port", help="RCP serial port (default: config, else the only Espressif USB-JTAG device)")
    ap.add_argument("--pan", help="Thread PAN ID, e.g. 0x1234 (default: dataset, config, else learned)")
    ap.add_argument("--mesh-local-prefix", help="mesh-local prefix, e.g. fd11:2233:4455:6677::")
    ap.add_argument("--key-seq", type=int, default=0, help="initial key sequence (default 0, learned from MLE)")
    ap.add_argument("--no-reset", action="store_true", help="don't reset the RCP at start")
    ap.add_argument("-w", "--pcap", help="also write the capture to this pcap file (802.15.4 TAP)")
    ap.add_argument("-r", "--replay", help="read frames from a pcap instead of the radio")
    ap.add_argument("--realtime", action="store_true", help="with --replay: keep the original pacing")
    ap.add_argument("-t", "--timeout", type=float, help="stop after SEC seconds")
    ap.add_argument("--no-remember", action="store_true",
                    help="don't use or update the devices remembered from earlier runs "
                         "(~/.config/thread-cli/devices.json)")
    ap.add_argument("--json", action="store_true", help="no UI: capture (default 30 s), print JSON")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    a = ap.parse_args(argv)
    a.config = cfg = Config()
    if cfg.error:
        ap.error(f"config: {cfg.error}")
    if a.port is None:
        a.port = cfg.get("port")

    a.ds = parse_dataset(_hex(a.dataset)) if a.dataset else {}
    key = None
    if a.key:
        key = _hex(a.key)
    elif a.key_file:
        key = _hex(open(os.path.expanduser(a.key_file)).read())
    elif a.ds.get("network_key"):
        key = a.ds["network_key"]
    elif os.environ.get("THREAD_NETWORK_KEY"):
        key = _hex(os.environ["THREAD_NETWORK_KEY"])
    elif default_key_file():
        a.key_file = default_key_file()
        key = _hex(open(a.key_file).read())
    if key is not None and len(key) != 16:
        ap.error("network key must be 16 bytes (32 hex digits)")
    a.key_bytes = key
    if a.channel is None:
        a.channel = a.ds.get("channel") or cfg.get("channel") or 11
    if not 11 <= a.channel <= 26:
        ap.error("channel must be 11-26")
    cpan = cfg.get("pan")
    a.pan_id = (int(a.pan, 0) if a.pan else a.ds.get("pan") if a.ds.get("pan") is not None
                else int(cpan, 0) if isinstance(cpan, str) else cpan)
    a.mlp = None
    if a.mesh_local_prefix:
        import ipaddress
        a.mlp = ipaddress.IPv6Network(a.mesh_local_prefix.split("/")[0] + "/64", strict=False) \
            .network_address.packed[:8]
    elif a.ds.get("mesh_local_prefix"):
        a.mlp = a.ds["mesh_local_prefix"]
    return a


class Capture:
    """Glue between a frame source thread and the single-threaded store."""

    def __init__(self, a):
        self.a = a
        km = crypto.KeyManager(a.key_bytes, a.key_seq) if a.key_bytes else None
        self.store = Store(km, thread_pan=a.pan_id, mesh_local_prefix=a.mlp,
                           network_name=a.ds.get("network_name"))
        self.q = queue.SimpleQueue()
        self.writer = pcap.PcapWriter(a.pcap) if a.pcap else None
        if a.replay:
            self.src = pcap.PcapSource(a.replay, realtime=a.realtime)
            self.port = a.replay
        else:
            from .spinel import SpinelSniffer
            self.port = a.port or find_port()
            self.src = SpinelSniffer(self.port, a.channel, reset=not a.no_reset)
        self.channel = a.channel
        self.memory = None if a.no_remember or self.store.km is None else DeviceMemory()
        self.memory_pan = None
        self.saved_at = time.time()
        self._load_memory()
        self.src.start(self.q.put)

    def _load_memory(self):
        pan = self.store.thread_pan
        if self.memory is None or pan is None or pan == self.memory_pan:
            return
        self.memory_pan = pan
        self.store.remember(self.memory.load(pan))

    def save_memory(self):
        if self.memory is None or self.memory_pan is None:
            return
        snap = self.store.snapshot()
        if snap:
            try:
                self.memory.save(self.memory_pan, snap)
            except OSError as e:
                self.memory.error = str(e)
        self.saved_at = time.time()

    def drain(self, limit=5000):
        n = 0
        while n < limit:
            try:
                rx = self.q.get_nowait()
            except queue.Empty:
                break
            if self.writer:
                self.writer.write(rx)
            if rx.channel and self.a.replay:
                self.channel = rx.channel
            self.store.ingest(rx)
            n += 1
        if self.memory_pan != self.store.thread_pan:
            self._load_memory()                     # PAN learned from the traffic
        if time.time() - self.saved_at > 30:
            self.save_memory()
        return n

    @property
    def finished(self):
        return getattr(self.src, "done", False) and self.q.empty()

    @property
    def error(self):
        return getattr(self.src, "error", None)

    def set_channel(self, ch):
        self.src.set_channel(ch)
        self.channel = ch

    def close(self):
        self.src.stop()
        self.save_memory()
        if self.writer:
            self.writer.close()


def to_json(store: Store, names=None):
    names = names or {}
    devs = []
    for d in sorted(store.devices.values(), key=lambda d: (not d.thread, d.rloc16 or 0xFFFF)):
        devs.append({
            "ext": d.ext.hex() if d.ext else None,
            "mac": d.ext.hex(":") if d.ext else None,
            "rloc16": f"0x{d.rloc16:04x}" if d.rloc16 is not None else None,
            "pan": f"0x{d.pan:04x}" if d.pan is not None else None,
            "thread": d.thread,
            "name": names.get(d.ext.hex(), "") if d.ext else "",
            "role": store.role(d),
            "mode": d.mode,
            "version": d.version,
            "frames": d.frames,
            "counts": dict(d.counts),
            "rssi": {"last": d.rssi_last, "avg": round(d.rssi_avg, 1) if d.rssi_avg is not None else None,
                     "min": d.rssi_min, "max": d.rssi_max, "n": d.rssi_n},
            "lqi": d.lqi_last,
            "mle": dict(d.mle_counts),
            "addresses": [{"address": a, "kind": k, "origin": o} for a, k, o in store.addresses(d)],
            "leader": d.leader,
            "routes": d.route,
            "first_seen": d.first,
            "last_seen": d.last,
        })
    s = store.stats
    return {"network": {"name": store.network_name,
                        "pan": f"0x{store.thread_pan:04x}" if store.thread_pan is not None else None,
                        "mesh_local_prefix": store.mesh_local_prefix.hex() if store.mesh_local_prefix else None,
                        "key_seq": store.km.seq if store.km else None,
                        "leader": store.leader},
            "stats": vars(s), "devices": devs}


def main(argv=None):
    a = parse_args(argv)
    if a.key_bytes is None:
        print("warning: no network key (--key/--dataset): frames will not be decrypted", file=sys.stderr)
    try:
        cap = Capture(a)
    except Exception as e:
        sys.exit(f"thread-cli: {e}")
    try:
        if a.json:
            end = time.time() + (a.timeout or (1e9 if a.replay else 30))
            while time.time() < end and not cap.finished and not (cap.error and not a.replay):
                if not cap.drain():
                    time.sleep(0.05)
            cap.drain(10 ** 9)
            if cap.error:
                print(f"source error: {cap.error}", file=sys.stderr)
            json.dump(to_json(cap.store, a.config.names), sys.stdout, indent=2, default=str)
            print()
            return 0
        from .ui import run_ui
        return run_ui(cap, a)
    finally:
        cap.close()


if __name__ == "__main__":
    sys.exit(main())
