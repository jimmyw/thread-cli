"""Thread key derivation and AES-CCM* (MAC and MLE security)."""
import hashlib
import hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


class KeyManager:
    """Derives the per-sequence MLE and MAC keys from the Thread network key."""

    def __init__(self, network_key: bytes, key_seq: int = 0):
        if len(network_key) != 16:
            raise ValueError("network key must be 16 bytes")
        self.network_key = network_key
        self.seq = key_seq
        self._cache = {}

    def keys(self, seq):
        k = self._cache.get(seq)
        if k is None:
            d = hmac.new(self.network_key, seq.to_bytes(4, "big") + b"Thread", hashlib.sha256).digest()
            k = self._cache[seq] = (d[:16], d[16:])   # (MLE key, MAC key)
        return k

    def mle_key(self, seq):
        return self.keys(seq)[0]

    def mac_key(self, seq):
        return self.keys(seq)[1]

    def seq_for_mac_index(self, idx):
        """MAC frames carry only key index = (seq & 0x7f) + 1; pick the sequence nearest the current one."""
        low = (idx - 1) & 0x7F
        cand = (self.seq & ~0x7F) | low
        return min((c for c in (cand - 128, cand, cand + 128) if c >= 0),
                   key=lambda c: abs(c - self.seq))

    def observe_seq(self, seq):
        if seq > self.seq:
            self.seq = seq


def nonce(ext: bytes, frame_counter: int, level: int) -> bytes:
    return ext + frame_counter.to_bytes(4, "big") + bytes([level])


def ccm_decrypt(key, nonce_, aad, ciphertext, mic, encrypted=True):
    """Return plaintext, or None if the MIC does not verify."""
    if not mic:
        return None
    try:
        c = AESCCM(key, tag_length=len(mic))
        if encrypted:
            return c.decrypt(nonce_, ciphertext + mic, aad)
        c.decrypt(nonce_, mic, aad + ciphertext)
        return ciphertext
    except (InvalidTag, ValueError):
        return None


def ccm_encrypt(key, nonce_, aad, plaintext, mic_len=4):
    out = AESCCM(key, tag_length=mic_len).encrypt(nonce_, plaintext, aad)
    return out[:-mic_len], out[-mic_len:]
