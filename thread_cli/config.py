"""User config in ~/.config/thread-cli/config.json:

    {
      "port": "/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_XX:XX:XX:XX:XX:XX-if00",
      "pan": "0x1234",
      "channel": 25,
      "names": {"9a3c51e2d07b44f1": "kitchen sensor"}
    }

port, pan and channel are defaults for the command-line options. names maps extended addresses to
names given with N in the UI; the extended address is the only identifier that survives a reattach
(RLOC16s change). Unknown keys are kept when the file is rewritten.
"""
import json
import os

DEFAULT_KEY_FILES = ["~/.config/thread-cli/networkkey", "~/.config/thread-logger/networkkey"]


def config_dir():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "thread-cli")


def default_key_file():
    for p in DEFAULT_KEY_FILES:
        p = os.path.expanduser(p)
        if os.path.isfile(p):
            return p
    return None


class Config:
    def __init__(self, path=None):
        self.path = path or os.path.join(config_dir(), "config.json")
        self.data: dict = {}
        self.error = None
        self.load()

    def load(self):
        try:
            with open(self.path) as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("top level must be an object")
            self.data = data
            self.error = None
        except FileNotFoundError:
            self.data = {}
        except (OSError, ValueError) as e:
            self.error = f"{self.path}: {e}"

    @property
    def names(self) -> dict:
        n = self.data.get("names")
        return {k.lower(): str(v) for k, v in n.items() if v} if isinstance(n, dict) else {}

    def get(self, key, default=None):
        return self.data.get(key, default)

    def name(self, ext: bytes | None) -> str:
        return self.names.get(ext.hex(), "") if ext else ""

    def set_name(self, ext: bytes, name: str):
        """Set (or with an empty name, remove) a name and save. Re-reads the file first so edits
        made meanwhile (by hand or by another thread-cli) are kept."""
        self.load()
        if self.error:
            raise OSError(self.error)
        names = self.names
        name = name.strip()
        if name:
            names[ext.hex()] = name
        else:
            names.pop(ext.hex(), None)
        self.data["names"] = dict(sorted(names.items()))
        self.save()

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
            f.write("\n")
        os.replace(tmp, self.path)


class DeviceMemory:
    """Devices learned in earlier runs, in ~/.config/thread-cli/devices.json, per PAN:

        {"networks": {"0x1234": {"devices": {"<ext hex>": {"rloc16": "0x4c75", "mode": 4,
            "version": 5, "timeout": 240, "addresses": [...], "first_seen": t, "last_seen": t}}}}}

    A sleepy child only reveals its extended address in MLE (attach, re-attach); otherwise it sends
    MAC-encrypted polls from its RLOC16, which can only be decrypted with that extended address in
    the nonce. Remembered addresses are tried for those frames, so a child seen in any earlier run
    (or replayed capture) is identified by its first poll. A wrong address never matches: the MIC
    only verifies with the right one.
    """

    FORGET_AFTER = 90 * 86400

    def __init__(self, path=None):
        self.path = path or os.path.join(config_dir(), "devices.json")
        self.error = None

    def _read(self) -> dict:
        try:
            with open(self.path) as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as e:
            self.error = f"{self.path}: {e}"
            return {}

    def load(self, pan: int) -> dict:
        nets = self._read().get("networks", {})
        devs = nets.get(f"0x{pan:04x}", {}).get("devices", {})
        return {k.lower(): v for k, v in devs.items() if isinstance(v, dict)}

    def save(self, pan: int, devices: dict):
        """Merge `devices` (ext hex -> entry) into the file; entries not given are kept."""
        if self.error:
            return
        data = self._read()
        if self.error:
            return
        net = data.setdefault("networks", {}).setdefault(f"0x{pan:04x}", {})
        old = net.get("devices", {})
        for k, v in devices.items():
            prev = old.get(k, {})
            if prev.get("first_seen"):
                v["first_seen"] = min(prev["first_seen"], v.get("first_seen") or prev["first_seen"])
            if prev.get("last_seen", 0) > v.get("last_seen", 0):     # replaying an older capture
                prev.update({f: v[f] for f in ("first_seen",) if f in v})
                continue
            for f in ("mode", "version", "timeout"):
                if v.get(f) is None and prev.get(f) is not None:
                    v[f] = prev[f]
            old[k] = v
        newest = max([v.get("last_seen", 0) for v in old.values()] + [0])
        net["devices"] = {k: v for k, v in sorted(old.items())
                          if newest - v.get("last_seen", 0) < self.FORGET_AFTER}
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            json.dump(data, f, indent=1)
            f.write("\n")
        os.replace(tmp, self.path)
