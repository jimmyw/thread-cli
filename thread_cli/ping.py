"""In-process ICMPv6 echo using unprivileged datagram ping sockets (net.ipv4.ping_group_range)."""
import os
import socket
import struct
import time

INTERVAL = 1.0
TIMEOUT = 12.0       # sleepy Thread children answer only when they next poll their parent


class Ping:
    def __init__(self, addr: str):
        self.addr = addr
        self.sent = self.received = self.lost = 0
        self.last = self.min = self.max = None
        self.total = 0.0
        self.error = None
        self.running = True
        self.inflight = {}
        self.seq = 0
        self.next_send = 0.0
        self.sock = None
        try:
            self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6)
            self.sock.setblocking(False)
        except OSError as e:
            self.error = f"cannot open ICMPv6 socket: {e.strerror}"
            self.running = False

    def fileno(self):
        return self.sock.fileno() if self.sock else -1

    def stop(self):
        self.running = False

    def close(self):
        self.running = False
        if self.sock:
            self.sock.close()
            self.sock = None

    def tick(self, now):
        if not self.sock:
            return
        for s, t in list(self.inflight.items()):
            if now - t > TIMEOUT:
                del self.inflight[s]
                self.lost += 1
        if self.running and now >= self.next_send:
            self.seq = (self.seq + 1) & 0xFFFF
            pkt = struct.pack(">BBHHH", 128, 0, 0, 0, self.seq) + struct.pack(">d", now) + os.urandom(8)
            try:
                self.sock.sendto(pkt, (self.addr, 0, 0, 0))
                self.sent += 1
                self.inflight[self.seq] = now
                self.error = None
            except OSError as e:
                self.error = e.strerror or str(e)
            self.next_send = now + INTERVAL
        self._recv()

    def _recv(self):
        while self.sock:
            try:
                data = self.sock.recv(2048)
            except BlockingIOError:
                return
            except OSError as e:
                self.error = e.strerror
                return
            if len(data) < 8 or data[0] != 129:
                continue
            seq = struct.unpack_from(">H", data, 6)[0]
            t = self.inflight.pop(seq, None)
            if t is None:
                continue
            rtt = (time.time() - t) * 1000
            self.received += 1
            self.last = rtt
            self.min = rtt if self.min is None else min(self.min, rtt)
            self.max = rtt if self.max is None else max(self.max, rtt)
            self.total += rtt

    @property
    def avg(self):
        return self.total / self.received if self.received else None

    @property
    def loss(self):
        resolved = self.received + self.lost
        return 100.0 * self.lost / resolved if resolved else 0.0

    def grade(self):
        """'good' / 'warn' / 'bad' like mdns-cli."""
        if self.error and not self.received:
            return "bad"
        if self.received + self.lost == 0:
            return "warn" if self.sent > 3 else "good"      # still waiting for the first answer
        if self.loss >= 50 or not self.received:
            return "bad"
        if self.loss > 0 or (self.avg or 0) > 20:
            return "warn"
        return "good"
