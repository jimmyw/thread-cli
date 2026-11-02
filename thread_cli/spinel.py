"""Spinel over HDLC-lite: just enough to run an OpenThread RCP as a promiscuous sniffer."""
import struct
import threading
import time
from dataclasses import dataclass

HDLC_FLAG, HDLC_ESC = 0x7E, 0x7D
FCS_INIT, FCS_GOOD = 0xFFFF, 0xF0B8

CMD_RESET = 1
CMD_PROP_VALUE_SET = 3
CMD_PROP_VALUE_IS = 6

PROP_LAST_STATUS = 0x00
PROP_NCP_VERSION = 0x02
PROP_PHY_ENABLED = 0x20
PROP_PHY_CHAN = 0x21
PROP_MAC_RAW_STREAM_ENABLED = 0x37
PROP_MAC_FILTER_MODE = 0x38
PROP_STREAM_RAW = 0x71

MAC_FILTER_MODE_MONITOR = 2


def _mkfcstab():
    tab = []
    for b in range(256):
        fcs = b
        for _ in range(8):
            fcs = (fcs >> 1) ^ 0x8408 if fcs & 1 else fcs >> 1
        tab.append(fcs & 0xFFFF)
    return tab


_FCSTAB = _mkfcstab()


def fcs16(data, fcs=FCS_INIT):
    for b in data:
        fcs = (fcs >> 8) ^ _FCSTAB[(fcs ^ b) & 0xFF]
    return fcs


def hdlc_encode(payload: bytes) -> bytes:
    fcs = fcs16(payload) ^ 0xFFFF
    out = bytearray([HDLC_FLAG])
    for b in payload + struct.pack("<H", fcs):
        if b in (HDLC_FLAG, HDLC_ESC, 0x11, 0x13, 0xF8):
            out += bytes([HDLC_ESC, b ^ 0x20])
        else:
            out.append(b)
    out.append(HDLC_FLAG)
    return bytes(out)


class HdlcDecoder:
    def __init__(self):
        self.buf = bytearray()
        self.esc = False
        self.bad = 0

    def feed(self, data: bytes):
        """Yield complete, FCS-checked frames (without FCS)."""
        for b in data:
            if b == HDLC_FLAG:
                if len(self.buf) >= 3:
                    if fcs16(self.buf) == FCS_GOOD:
                        yield bytes(self.buf[:-2])
                    else:
                        self.bad += 1
                self.buf.clear()
                self.esc = False
            elif b == HDLC_ESC:
                self.esc = True
            else:
                self.buf.append(b ^ 0x20 if self.esc else b)
                self.esc = False


def packed_uint(b, pos=0):
    """Spinel packed unsigned int (EXI-style 7-bit groups). Returns (value, new_pos)."""
    val = shift = 0
    while True:
        c = b[pos]
        pos += 1
        val |= (c & 0x7F) << shift
        if not c & 0x80:
            return val, pos
        shift += 7


@dataclass
class RxFrame:
    t: float          # host wall-clock time
    psdu: bytes       # MAC frame without FCS
    rssi: int | None
    lqi: int | None
    channel: int | None


def parse_stream_raw(value: bytes, t: float) -> RxFrame | None:
    if len(value) < 2:
        return None
    n = struct.unpack_from("<H", value)[0]
    frame = value[2:2 + n]
    meta = value[2 + n:]
    rssi = lqi = chan = None
    if len(meta) >= 8:
        rssi = struct.unpack_from("<b", meta, 0)[0]
        # meta: rssi, noise, flags(u16), struct len(u16), channel, lqi, ...
        chan, lqi = meta[6], meta[7]
        if rssi == 127 or rssi == -128:
            rssi = None
    if len(frame) < 3:
        return None
    return RxFrame(t, frame[:-2], rssi, lqi, chan)  # strip FCS


class SpinelError(Exception):
    pass


class SpinelSniffer:
    """Owns the serial port; a background thread pushes RxFrame objects into `sink(frame)`."""

    def __init__(self, port: str, channel: int, reset: bool = True):
        import serial  # pyserial
        self.port = port
        self.channel = channel
        self.ser = serial.Serial(port, 460800, timeout=0.1)
        self.dec = HdlcDecoder()
        self.tid = 0
        self.version = ""
        self.error = None
        self._stop = threading.Event()
        self._pending = []
        if reset:
            self._send(CMD_RESET)
            time.sleep(1.0)
            self.ser.reset_input_buffer()
        self.version = self._get_str(PROP_NCP_VERSION)
        self._set(PROP_PHY_ENABLED, b"\x01")
        self._set(PROP_MAC_FILTER_MODE, bytes([MAC_FILTER_MODE_MONITOR]))
        self._set(PROP_PHY_CHAN, bytes([channel]))
        self._set(PROP_MAC_RAW_STREAM_ENABLED, b"\x01")

    def _send(self, cmd, prop=None, value=b""):
        self.tid = self.tid % 15 + 1
        payload = bytes([0x80 | self.tid, cmd])
        if prop is not None:
            payload += bytes([prop]) + value
        self.ser.write(hdlc_encode(payload))
        return self.tid

    def _transact(self, cmd, prop, value=b"", timeout=2.0):
        tid = self._send(cmd, prop, value)
        end = time.time() + timeout
        while time.time() < end:
            data = self.ser.read(self.ser.in_waiting or 1)
            for fr in self.dec.feed(data):
                if len(fr) < 3:
                    continue
                if fr[0] & 0x0F != tid or fr[1] != CMD_PROP_VALUE_IS:
                    self._pending.append(fr)
                    continue
                p, pos = packed_uint(fr, 2)
                if p == prop:
                    return fr[pos:]
                if p == PROP_LAST_STATUS:
                    st, _ = packed_uint(fr, pos)
                    raise SpinelError(f"prop 0x{prop:02x}: status {st}")
        raise SpinelError(f"no reply from RCP for prop 0x{prop:02x} (is it running ot_rcp, "
                          "and not stuck in download mode?)")

    def _get_str(self, prop):
        try:
            return self._transact(2, prop).split(b"\0")[0].decode(errors="replace")
        except SpinelError:
            return ""

    def _set(self, prop, value):
        self._transact(CMD_PROP_VALUE_SET, prop, value)

    def set_channel(self, channel):
        # Called from the UI thread while the reader runs: just send; the reply is ignored.
        self.tid = self.tid % 15 + 1
        self.ser.write(hdlc_encode(bytes([0x80 | self.tid, CMD_PROP_VALUE_SET, PROP_PHY_CHAN, channel])))
        self.channel = channel

    def run(self, sink):
        def handle(fr):
            if len(fr) < 3 or fr[1] != CMD_PROP_VALUE_IS:
                return
            p, pos = packed_uint(fr, 2)
            if p == PROP_STREAM_RAW:
                rx = parse_stream_raw(fr[pos:], time.time())
                if rx:
                    sink(rx)

        for fr in self._pending:
            handle(fr)
        self._pending.clear()
        try:
            while not self._stop.is_set():
                data = self.ser.read(self.ser.in_waiting or 1)
                for fr in self.dec.feed(data):
                    handle(fr)
        except Exception as e:  # device unplugged etc.
            self.error = str(e)

    def start(self, sink):
        th = threading.Thread(target=self.run, args=(sink,), daemon=True)
        th.start()
        return th

    def stop(self):
        self._stop.set()
        try:
            self.ser.close()
        except Exception:
            pass
