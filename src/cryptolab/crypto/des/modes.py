"""
DES-CBC mode encryption and decryption

CBC (Cipher Block Chaining)

  Encrypt: C_i = DES_K(P_i XOR C_{i-1}),  C_0 = IV
  Decrypt: P_i = DES_K^-1(C_i) XOR C_{i-1}, C_0 = IV

Padding: PKCS#7 (pad to a multiple of 8 bytes)
"""

from __future__ import annotations
from typing import Any, Dict, List

from cryptolab.crypto.des.key_schedule import generate_round_keys
from cryptolab.crypto.des.core import des_block

_BLOCK = 8  # DES block size in bytes


# ── padding ──────────────────────────────────────────────────────────────────

def _pad(data: bytes) -> bytes:
    """PKCS#7 padding to a multiple of _BLOCK bytes."""
    pad_len = _BLOCK - (len(data) % _BLOCK)
    return data + bytes([pad_len] * pad_len)


def _unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding (raises ValueError on corrupt padding)."""
    if not data:
        raise ValueError("Empty data, cannot unpad")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > _BLOCK:
        raise ValueError(f"Invalid PKCS#7 pad byte: {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("PKCS#7 padding is corrupt")
    return data[:-pad_len]


# ── CBC encrypt / decrypt ─────────────────────────────────────────────────────

def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Encrypt plaintext using DES-CBC.

    Args:
        plaintext: arbitrary-length bytes
        key:       8-byte DES key
        iv:        8-byte initialisation vector

    Returns:
        Ciphertext bytes (length is a multiple of 8).
    """
    if len(key) != _BLOCK:
        raise ValueError(f"DES key must be {_BLOCK} bytes")
    if len(iv) != _BLOCK:
        raise ValueError(f"IV must be {_BLOCK} bytes")

    round_keys = generate_round_keys(int.from_bytes(key, "big"))
    padded = _pad(plaintext)

    ciphertext = bytearray()
    prev = int.from_bytes(iv, "big")

    for i in range(0, len(padded), _BLOCK):
        p_int = int.from_bytes(padded[i : i + _BLOCK], "big")
        c_int = des_block(p_int ^ prev, round_keys, encrypt=True)
        ciphertext += c_int.to_bytes(_BLOCK, "big")
        prev = c_int

    return bytes(ciphertext)


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt ciphertext using DES-CBC

    ciphertext: bytes produced by encrypt_cbc (multiple of 8 bytes)
    key:        8-byte DES key
    iv:         8-byte initialisation vector

    Returns:
    Original plaintext bytes
    """
    if len(key) != _BLOCK:
        raise ValueError(f"DES key must be {_BLOCK} bytes")
    if len(iv) != _BLOCK:
        raise ValueError(f"IV must be {_BLOCK} bytes")
    if len(ciphertext) % _BLOCK != 0:
        raise ValueError("Ciphertext length must be a multiple of 8")

    round_keys = generate_round_keys(int.from_bytes(key, "big"))

    plaintext = bytearray()
    prev = int.from_bytes(iv, "big")

    for i in range(0, len(ciphertext), _BLOCK):
        c_int = int.from_bytes(ciphertext[i : i + _BLOCK], "big")
        p_int = des_block(c_int, round_keys, encrypt=False) ^ prev
        plaintext += p_int.to_bytes(_BLOCK, "big")
        prev = c_int

    return _unpad(bytes(plaintext))


def encrypt_cbc_trace(
    plaintext: bytes, key: bytes, iv: bytes
) -> Dict[str, Any]:
    """encrypt_cbc with step-by-step trace output."""
    trace_summary: List[str] = [
        "DES-CBC ENCRYPT",
        f"Plaintext length: {len(plaintext)} bytes",
        f"IV: {iv.hex()}",
    ]
    trace_full: List[str] = list(trace_summary)

    ct = encrypt_cbc(plaintext, key, iv)

    n_blocks = len(ct) // _BLOCK
    trace_summary.append(f"Encrypted {n_blocks} block(s) -> {len(ct)} bytes ciphertext")
    trace_full.append(f"Padded plaintext (hex): {_pad(plaintext).hex()}")

    round_keys = generate_round_keys(int.from_bytes(key, "big"))
    prev = int.from_bytes(iv, "big")
    padded = _pad(plaintext)

    for i in range(0, len(padded), _BLOCK):
        blk_idx = i // _BLOCK
        p_int = int.from_bytes(padded[i : i + _BLOCK], "big")
        xored = p_int ^ prev
        c_int = des_block(xored, round_keys, encrypt=True)
        trace_full.append(
            f"Block {blk_idx}: P={p_int:#018x} XOR prev={prev:#018x}"
            f" -> DES -> C={c_int:#018x}"
        )
        prev = c_int

    trace_full.append(f"Ciphertext (hex): {ct.hex()}")

    return {
        "ciphertext":    ct,
        "trace_summary": trace_summary,
        "trace_full":    trace_full,
    }


def decrypt_cbc_trace(
    ciphertext: bytes, key: bytes, iv: bytes
) -> Dict[str, Any]:
    """decrypt_cbc with step-by-step trace output."""
    trace_summary: List[str] = [
        "DES-CBC DECRYPT",
        f"Ciphertext length: {len(ciphertext)} bytes",
        f"IV: {iv.hex()}",
    ]
    trace_full: List[str] = list(trace_summary)

    pt = decrypt_cbc(ciphertext, key, iv)

    n_blocks = len(ciphertext) // _BLOCK
    trace_summary.append(f"Decrypted {n_blocks} block(s) -> {len(pt)} bytes plaintext")

    round_keys = generate_round_keys(int.from_bytes(key, "big"))
    prev = int.from_bytes(iv, "big")

    for i in range(0, len(ciphertext), _BLOCK):
        blk_idx = i // _BLOCK
        c_int = int.from_bytes(ciphertext[i : i + _BLOCK], "big")
        p_int = des_block(c_int, round_keys, encrypt=False) ^ prev
        trace_full.append(
            f"Block {blk_idx}: C={c_int:#018x} -> DES^-1 XOR prev={prev:#018x}"
            f" -> P={p_int:#018x}"
        )
        prev = c_int

    trace_full.append(f"Plaintext (after unpad): {pt!r}")

    return {
        "plaintext":     pt,
        "trace_summary": trace_summary,
        "trace_full":    trace_full,
    }
