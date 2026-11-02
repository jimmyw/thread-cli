"""pcap reading (for --replay) and writing (for --pcap) of 802.15.4 frames.

Writes LINKTYPE_IEEE802_15_4_TAP (283) so RSSI/LQI/channel survive into Wireshark; reads that
and LINKTYPE_IEEE802_15_4_WITHFCS (195).
"""
import struct
import time

from .spinel import RxFrame

DLT_WITHFCS = 195
DLT_TAP = 283


def crc16_kermit(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc


class PcapWriter:
    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, DLT_TAP))
        self.f.flush()

    def write(self, rx: RxFrame):
        frame = rx.psdu + struct.pack("<H", crc16_kermit(rx.psdu))
        tlvs = b""
        tlvs += struct.pack("<HHI", 0, 1, 1)                                # FCS type: 16-bit
        if rx.channel is not None:
            tlvs += struct.pack("<HHHBx", 3, 3, rx.channel, 0)             # channel, page 0
        if rx.rssi is not None:
            tlvs += struct.pack("<HHf", 1, 4, float(rx.rssi))              # RSS dBm
        if rx.lqi is not None:
            tlvs += struct.pack("<HHBxxx", 10, 1, rx.lqi)                  # LQI
        hdr = struct.pack("<BBH", 0, 0, 4 + len(tlvs)) + tlvs
        sec = int(rx.t)
        usec = int((rx.t - sec) * 1e6)
        n = len(hdr) + len(frame)
        self.f.write(struct.pack("<IIII", sec, usec, n, n) + hdr + frame)
        self.f.flush()

    def close(self):
        self.f.close()


def read_pcap(path):
    """Yield RxFrame for each packet. Timestamps are taken from the file."""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = struct.unpack_from("<I", gh)[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            e = "<"
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            e = ">"
        else:
            raise ValueError(f"{path}: not a pcap file (pcapng is not supported)")
        nano = magic in (0xA1B23C4D, 0x4D3CB2A1)
        dlt = struct.unpack_from(e + "I", gh, 20)[0]
        if dlt not in (DLT_TAP, DLT_WITHFCS):
            raise ValueError(f"{path}: link type {dlt} is not 802.15.4 (195 or 283)")
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            sec, frac, incl, _orig = struct.unpack(e + "IIII", ph)
            data = f.read(incl)
            t = sec + frac / (1e9 if nano else 1e6)
            rssi = lqi = chan = None
            if dlt == DLT_TAP:
                hlen = struct.unpack_from("<H", data, 2)[0]
                pos = 4
                while pos + 4 <= hlen:
                    typ, ln = struct.unpack_from("<HH", data, pos)
                    v = data[pos + 4:pos + 4 + ln]
                    if typ == 1 and ln == 4:
                        rssi = round(struct.unpack("<f", v)[0])
                    elif typ == 10 and ln >= 1:
                        lqi = v[0]
                    elif typ == 3 and ln >= 2:
                        chan = struct.unpack_from("<H", v)[0]
                    pos += 4 + ln + (-ln % 4)
                data = data[hlen:]
            if len(data) >= 5:
                yield RxFrame(t, data[:-2], rssi, lqi, chan)


class PcapSource:
    """Feeds a pcap file into a sink, optionally paced in real time."""

    def __init__(self, path, realtime=False):
        self.path = path
        self.realtime = realtime
        self.done = False
        self.error = None
        self.channel = None
        self.version = f"replay {path}"

    def run(self, sink):
        try:
            t0 = w0 = None
            for rx in read_pcap(self.path):
                if self.realtime:
                    if t0 is None:
                        t0, w0 = rx.t, time.time()
                    delay = (rx.t - t0) - (time.time() - w0)
                    if delay > 0:
                        time.sleep(delay)
                    rx.t = time.time()
                if rx.channel and not self.channel:
                    self.channel = rx.channel
                sink(rx)
        except Exception as e:
            self.error = str(e)
        self.done = True

    def start(self, sink):
        import threading
        th = threading.Thread(target=self.run, args=(sink,), daemon=True)
        th.start()
        return th

    def stop(self):
        pass

    def set_channel(self, channel):
        pass
