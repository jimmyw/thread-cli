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
