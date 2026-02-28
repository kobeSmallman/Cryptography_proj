from __future__ import annotations

"""
KDF

Derives an 8-byte DES key and an 8-byte IV from the Diffie-Hellman
shared secret s (an arbitrary-size integer).

Algorithm (manual, no external libraries):
  Encode s as big-endian bytes, zero-pad to a multiple of 8 bytes.
  Split into 8-byte blocks and XOR all blocks together → base[8].
  key = base with byte[0] XOR 0x01   (counter differentiation)
  iv  = base with byte[0] XOR 0x02

This gives deterministic, distinct key and IV from any shared secret.
"""

from typing import Any, Dict, List


def derive_des_key_iv(s: int) -> Dict[str, Any]:
    """
    Derive an 8-byte DES key and 8-byte IV from shared secret s.

    Returns a dict with:
        key            : bytes (8)
        iv             : bytes (8)
        trace_summary  : List[str]
        trace_full     : List[str]
    """
    trace_summary: List[str] = [
        "KDF: derive DES key and IV from DH shared secret s",
        f"Input s (bit_length={s.bit_length()})",
    ]
    trace_full: List[str] = list(trace_summary)

    # Step 1: encode s as big-endian bytes
    byte_len = max((s.bit_length() + 7) // 8, 1)
    s_bytes = s.to_bytes(byte_len, "big")

    trace_full.append(f"Step 1: s encoded as {byte_len} bytes (big-endian): {s_bytes.hex()}")

    # Step 2: zero-pad to the next multiple of 8
    pad_to = ((len(s_bytes) + 7) // 8) * 8
    s_padded = s_bytes.rjust(pad_to, b"\x00")

    n_blocks = pad_to // 8
    trace_full.append(f"Step 2: padded to {pad_to} bytes → {n_blocks} block(s) of 8 bytes")

    # Step 3: XOR-fold all 8-byte blocks into base[8]
    base = bytearray(8)
    for i in range(n_blocks):
        block = s_padded[i * 8 : i * 8 + 8]
        for j in range(8):
            base[j] ^= block[j]
        trace_full.append(f"  XOR block {i}: {block.hex()} → base so far: {base.hex()}")

    trace_summary.append(f"XOR-folded {n_blocks} block(s) → base material: {base.hex()}")

    # Step 4: derive key (counter byte 0x01) and iv (counter byte 0x02)
    key = bytearray(base)
    key[0] ^= 0x01
    iv = bytearray(base)
    iv[0] ^= 0x02

    key = bytes(key)
    iv  = bytes(iv)

    trace_full.append(f"Step 3: key = base XOR 0x01 at byte[0] = {key.hex()}")
    trace_full.append(f"Step 4: iv  = base XOR 0x02 at byte[0] = {iv.hex()}")

    trace_summary.append(f"key (hex): {key.hex()}")
    trace_summary.append(f"iv  (hex): {iv.hex()}")

    return {
        "key":           key,
        "iv":            iv,
        "trace_summary": trace_summary,
        "trace_full":    trace_full,
    }
