"""MeshCoP operational dataset TLVs (as printed by `dataset active -x` / the OTBR web UI)."""
import struct


def parse_dataset(b: bytes) -> dict:
    out = {}
    pos = 0
    while pos + 2 <= len(b):
        t, ln = b[pos], b[pos + 1]
        v = b[pos + 2:pos + 2 + ln]
        pos += 2 + ln
        if t == 0 and ln >= 3:
            out["channel"] = struct.unpack_from(">H", v, 1)[0]
        elif t == 1 and ln == 2:
            out["pan"] = struct.unpack(">H", v)[0]
        elif t == 2 and ln == 8:
            out["ext_pan"] = v.hex()
        elif t == 3:
            out["network_name"] = v.decode(errors="replace")
        elif t == 5 and ln == 16:
            out["network_key"] = bytes(v)
        elif t == 7 and ln == 8:
            out["mesh_local_prefix"] = bytes(v)
        elif t == 14 and ln == 8:
            out["active_timestamp"] = struct.unpack(">Q", v)[0] >> 16
    return out
