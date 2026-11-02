"""Round-trip tests: build encrypted Thread frames from scratch and check the store decodes them.

Run:  python3 -m unittest discover -s tests -v
"""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from thread_cli import crypto, lowpan, mle, spinel, wpan  # noqa: E402
from thread_cli.store import Store  # noqa: E402

KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
PAN = 0x1234
MLP = bytes.fromhex("fdde00ad00beef00")
ROUTER_EXT = bytes.fromhex("1122334455667788")
CHILD_EXT = bytes.fromhex("a1a2a3a4a5a6a7a8")


def ll(ext):
    return lowpan.LL_PREFIX + lowpan.mac_iid(ext)


def mac_header(src, dst, seq, secured, fc=0, key_index=1, ack=False):
    """2006-version data frame, PAN ID compression."""
    smode = 3 if isinstance(src, bytes) else 2
    dmode = 3 if isinstance(dst, bytes) else 2
    fcf = 1 | (secured << 3) | (ack << 5) | (1 << 6) | (dmode << 10) | (1 << 12) | (smode << 14)
    h = struct.pack("<HB", fcf, seq) + struct.pack("<H", PAN)
    h += dst[::-1] if isinstance(dst, bytes) else struct.pack("<H", dst)
    h += src[::-1] if isinstance(src, bytes) else struct.pack("<H", src)
    if secured:
        h += bytes([0x05 | (1 << 3)]) + struct.pack("<I", fc) + bytes([key_index])
    return h


def mle_udp(km, src_ext, dst_ip, command, tlvs, fc=7, seq=0):
    aux = bytes([0x15]) + struct.pack("<I", fc) + struct.pack(">I", seq) + bytes([(seq & 0x7F) + 1])
    body = bytes([command]) + b"".join(bytes([t, len(v)]) + v for t, v in tlvs)
    src_ip = ll(src_ext)
    ct, mic = crypto.ccm_encrypt(km.mle_key(seq), crypto.nonce(src_ext, fc, 5), src_ip + dst_ip + aux, body)
    return src_ip, b"\x00" + aux + ct + mic


def iphc_udp_ll(src_ext, dst_ip, payload, port=19788):
    # IPHC: TF=11, NH=1 (NHC), HLIM=11 (255); SAC=0 SAM=11 (from MAC); M=1 DAM=11 (ff02::XX)
    b = bytes([0b01111111, 0b00111011]) + bytes([dst_ip[15]])
    b += bytes([0xF0]) + struct.pack(">HH", port, port) + b"\x00\x00"   # UDP NHC, ports inline, checksum
    return b + payload


class RoundTrip(unittest.TestCase):
    def setUp(self):
        self.km = crypto.KeyManager(KEY)
        self.st = Store(crypto.KeyManager(KEY), thread_pan=PAN, mesh_local_prefix=MLP)

    def feed(self, psdu, rssi=-60, t=1000.0):
        self.st.ingest(spinel.RxFrame(t, psdu, rssi, 200, 15))

    def advertisement(self, rloc, t=1000.0, rssi=-60):
        dst = bytes.fromhex("ff020000000000000000000000000001")
        leader = struct.pack(">IBBBB", 0xCAFEBABE, 64, 3, 4, rloc >> 10)
        mask = bytearray(8)
        mask[(rloc >> 10) // 8] |= 0x80 >> ((rloc >> 10) % 8)
        route = bytes([9]) + bytes(mask) + bytes([0x01])
        src_ip, udp = mle_udp(self.km, ROUTER_EXT, dst, 4,
                              [(mle.T_SOURCE, struct.pack(">H", rloc)), (mle.T_LEADER, leader),
                               (mle.T_ROUTE64, route)])
        self.assertEqual(src_ip, ll(ROUTER_EXT))
        self.feed(mac_header(ROUTER_EXT, 0xFFFF, 1, False) + iphc_udp_ll(ROUTER_EXT, dst, udp), rssi, t)

    def test_mle_advertisement(self):
        self.advertisement(0x2C00)
        d = self.st.devices[ROUTER_EXT.hex()]
        self.assertTrue(d.thread)
        self.assertEqual(d.rloc16, 0x2C00)
        self.assertEqual(d.mle_counts["Advertisement"], 1)
        self.assertEqual(self.st.role(d), "leader")
        self.assertEqual(d.route["routes"][0]["router_id"], 0x2C00 >> 10)
        self.assertEqual(d.rssi_last, -60)

    def test_wrong_key_does_not_decrypt(self):
        self.st.km = crypto.KeyManager(bytes(16))
        self.advertisement(0x2C00)
        d = self.st.devices[ROUTER_EXT.hex()]
        self.assertFalse(d.thread)
        self.assertEqual(d.counts["mle (undecrypted)"], 1)

    def test_child_short_address_resolved_by_trial_decryption(self):
        self.advertisement(0x2C00)
        # Child ID Response from router to child (link-local unicast) assigns RLOC16 0x2C05.
        src_ip, udp = mle_udp(self.km, ROUTER_EXT, ll(CHILD_EXT), 12,
                              [(mle.T_SOURCE, struct.pack(">H", 0x2C00)),
                               (mle.T_ADDR16, struct.pack(">H", 0x2C05))], fc=8)
        iphc = bytes([0b01111111, 0b00110011]) + bytes([0xF0]) + struct.pack(">HH", 19788, 19788) + b"\0\0"
        self.feed(mac_header(ROUTER_EXT, CHILD_EXT, 2, False) + iphc + udp)
        child = self.st.devices[CHILD_EXT.hex()]
        self.assertEqual(child.rloc16, 0x2C05)
        # Now a MAC-secured data poll from the child using its short address.
        hdr = bytearray(mac_header(0x2C05, 0x2C00, 3, True, fc=42, ack=True))
        hdr[0] = (hdr[0] & ~7) | 3            # command frame
        n = crypto.nonce(CHILD_EXT, 42, 5)
        ct, mic = crypto.ccm_encrypt(self.km.mac_key(0), n, bytes(hdr), b"\x04")
        self.feed(bytes(hdr) + ct + mic, rssi=-80, t=1001.0)
        self.assertEqual(child.counts["poll"], 1)
        self.assertEqual(child.rssi_last, -80)
        self.assertEqual(self.st.role(child), "sleepy child")
        # ...and its immediate ack is attributed to the router.
        router = self.st.devices[ROUTER_EXT.hex()]
        self.feed(struct.pack("<HB", 0x0002, 3), rssi=-55, t=1001.0005)
        self.assertEqual(router.counts["ack"], 1)
        self.assertEqual(router.rssi_last, -55)

    def test_mac_decrypt_and_address_learning(self):
        self.advertisement(0x2C00)
        # Secured data frame from router (short src) carrying UDP from its ML-EID.
        mleid = MLP + bytes.fromhex("0102030405060708")
        dst = MLP + bytes.fromhex("000000fffe002c05")
        # IPHC: TF=11 NH=1 HLIM=10; CID=0 SAC=1 SAM=01 (64-bit IID); M=0 DAC=1 DAM=10 (16-bit)
        iphc = bytes([0b01111110, 0b01010110]) + mleid[8:] + dst[14:]
        iphc += bytes([0xF0]) + struct.pack(">HH", 5683, 5683) + b"\0\0" + b"hello"
        hdr = mac_header(0x2C00, 0x2C05, 9, True, fc=100)
        ct, mic = crypto.ccm_encrypt(self.km.mac_key(0), crypto.nonce(ROUTER_EXT, 100, 5), hdr, iphc)
        self.feed(hdr + ct + mic)
        d = self.st.devices[ROUTER_EXT.hex()]
        self.assertIn(lowpan.fmt_ip(mleid), d.addresses)
        self.assertIn("UDP 5683->5683", d.last_frame)


    def poll(self, short, parent, ext, fc):
        hdr = bytearray(mac_header(short, parent, 3, True, fc=fc, ack=True))
        hdr[0] = (hdr[0] & ~7) | 3            # command frame
        ct, mic = crypto.ccm_encrypt(self.km.mac_key(0), crypto.nonce(ext, fc, 5), bytes(hdr), b"\x04")
        return bytes(hdr) + ct + mic

    def test_forwarded_source_address_stays_with_child(self):
        self.advertisement(0x2C00)
        st = self.st
        child = st._by_ext(CHILD_EXT, PAN, 1000.0)
        st.map_short(PAN, 0x2C05, CHILD_EXT)
        router = st.devices[ROUTER_EXT.hex()]
        omr = "fd00:aaaa:bbbb:1:1:2:3:4"
        st.on_mesh.add(bytes.fromhex("fd00aaaabbbb0001"))
        st._learn_address(child, lowpan.ipaddress.IPv6Address(omr).packed)    # child -> parent
        st._learn_address(router, lowpan.ipaddress.IPv6Address(omr).packed)   # parent forwards
        self.assertIn(omr, child.addresses)
        self.assertNotIn(omr, router.addresses)
        # seen at the router first (child's frame missed), then the child registers it
        omr2 = "fd00:aaaa:bbbb:1:5:6:7:8"
        st._learn_address(router, lowpan.ipaddress.IPv6Address(omr2).packed)
        st._own(child, omr2, "registered")
        self.assertEqual(child.addresses[omr2], "registered")
        self.assertNotIn(omr2, router.addresses)

    def test_remembered_child_identified_by_first_poll(self):
        # A fresh run that never saw the child's MLE can't decrypt its polls...
        self.feed(self.poll(0x2C05, 0x2C00, CHILD_EXT, 42))
        self.assertNotIn(CHILD_EXT.hex(), self.st.devices)
        # ...unless an earlier run remembered it.
        st = Store(crypto.KeyManager(KEY), thread_pan=PAN, mesh_local_prefix=MLP)
        st.remember({CHILD_EXT.hex(): {"rloc16": "0x2c05", "mode": 4, "last_seen": 500.0,
                                       "addresses": ["fd00::1"]},
                     "0102030405060708": {"rloc16": "0x2c01"}})
        st.ingest(spinel.RxFrame(1000.0, self.poll(0x2C05, 0x2C00, CHILD_EXT, 43), -70, 200, 15))
        child = st.devices[CHILD_EXT.hex()]
        self.assertEqual((child.rloc16, child.mode, child.remembered), (0x2C05, 4, 500.0))
        self.assertEqual(child.counts["poll"], 1)
        self.assertEqual(child.addresses["fd00::1"], "remembered")
        self.assertEqual(st.role(child), "sleepy child")
        self.assertNotIn("0102030405060708", st.devices)
        snap = st.snapshot()[CHILD_EXT.hex()]
        self.assertEqual((snap["rloc16"], snap["mode"], snap["addresses"]), ("0x2c05", 4, ["fd00::1"]))

    def test_memory_file_merge(self):
        import tempfile
        from thread_cli.config import DeviceMemory
        with tempfile.TemporaryDirectory() as tmp:
            m = DeviceMemory(os.path.join(tmp, "devices.json"))
            m.save(PAN, {"aa": {"rloc16": "0x2c05", "mode": 4, "last_seen": 2000.0, "first_seen": 1000.0}})
            # an older replay doesn't overwrite newer data, but extends first_seen
            m.save(PAN, {"aa": {"rloc16": "0x2c09", "mode": None, "last_seen": 900.0, "first_seen": 800.0},
                         "bb": {"rloc16": "0x2c00", "last_seen": 1500.0}})
            got = m.load(PAN)
            self.assertEqual(got["aa"]["rloc16"], "0x2c05")
            self.assertEqual(got["aa"]["first_seen"], 800.0)
            self.assertIn("bb", got)
            self.assertEqual(m.load(0x9999), {})
            self.assertEqual(os.stat(m.path).st_mode & 0o777, 0o600)


class Parsing(unittest.TestCase):
    def test_hdlc_roundtrip(self):
        payload = bytes(range(256))
        dec = spinel.HdlcDecoder()
        self.assertEqual(list(dec.feed(spinel.hdlc_encode(payload))), [payload])

    def test_key_index_to_sequence(self):
        km = crypto.KeyManager(KEY, 130)
        self.assertEqual(km.seq_for_mac_index((130 & 0x7F) + 1), 130)
        self.assertEqual(km.seq_for_mac_index((131 & 0x7F) + 1), 131)
        self.assertEqual(km.seq_for_mac_index((127 & 0x7F) + 1), 127)

    def test_frame_versions(self):
        f = wpan.parse(struct.pack("<HB", 0x0002, 7))
        self.assertEqual((f.ftype, f.seq), (wpan.FT_ACK, 7))


class ConfigFile(unittest.TestCase):
    def test_names_roundtrip_keeps_other_keys(self):
        import json
        import tempfile
        from thread_cli.config import Config
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "thread-cli", "config.json")
            os.makedirs(os.path.dirname(path))
            with open(path, "w") as f:
                json.dump({"port": "/dev/ttyACM9", "pan": "0x1234"}, f)
            c = Config(path)
            c.set_name(ROUTER_EXT, "  köksbänk ")
            self.assertEqual(Config(path).name(ROUTER_EXT), "köksbänk")
            self.assertEqual(Config(path).get("port"), "/dev/ttyACM9")
            c.set_name(ROUTER_EXT, "")
            self.assertEqual(Config(path).name(ROUTER_EXT), "")
            self.assertEqual(Config(path).get("pan"), "0x1234")


if __name__ == "__main__":
    unittest.main()
