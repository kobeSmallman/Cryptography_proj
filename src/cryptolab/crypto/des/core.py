"""

DES single 64-bit block encrypt/decrypt

Algorithm (Feistel cipher, 16 rounds)

  1. Initial perm
  2. Split into L0 and R0 both 32 bit splits
  3. For i = 1..16:
       L_i = R_{i-1}
       R_i = L_{i-1} XOR f(R_{i-1}, K_i)
  4. Preoutput: swap -> R16 || L16
  5. Final Permutation FP (= IP^-1)

"""

from __future__ import annotations
from typing import Any, Dict, List

from cryptolab.crypto.des.tables import IP, FP, E, P, SBOXES


def _permute(block: int, table: List[int], input_bits: int) -> int:
    """Apply a perms table to an integer (table entries are 1-indexed from MSB)."""
    out = 0
    for bit_pos in table:
        out = (out << 1) | ((block >> (input_bits - bit_pos)) & 1)
    return out


def _feistel(R: int, round_key: int) -> int:
    """

    DES Feistel function f(R, K):

      1. Expand R from 32 to 48 bits via E
      2. XOR with 48-bit round key
      3. S-box substitution (8 S-boxes, 6 bits in -> 4 bits out each)
      4. Permutation P on the 32-bit result

    """
    # Expand R: 32 -> 48 bits
    expanded = _permute(R, E, 32)

    # XOR with round key
    xored = expanded ^ round_key

    # S-box substitution: process eight 6-bit groups left to right
    sbox_out = 0
    for i in range(8):
        six = (xored >> (42 - 6 * i)) & 0x3F   # bits [6i .. 6i + 5] from MSB
        row = ((six >> 5) & 1) * 2 + (six & 1) # outer bits: b1 * 2 + b6
        col = (six >> 1) & 0xF                  # inner 4 b2 b3 b4 b5
        sbox_out = (sbox_out << 4) | SBOXES[i][row][col]

    # Apply P permutation: 32 -> 32 bits
    return _permute(sbox_out, P, 32)


def des_block(block: int, round_keys: List[int], encrypt: bool = True) -> int:
    """

    Encrypt or decrypt one 64-bit block using DES.

    Args:
        block:      64-bit integer
        round_keys: list of 16 x 48-bit round keys (from generate_round_keys)
        encrypt:    True to encrypt, False to decrypt (reverses key order)

    Returns:
        64-bit integer resul

    """
    # Initial permutation
    block = _permute(block, IP, 64)

    # Split into 32-bit halves
    L = (block >> 32) & 0xFFFFFFFF
    R =  block        & 0xFFFFFFFF

    keys = round_keys if encrypt else list(reversed(round_keys))

    for k in keys:
        L, R = R, L ^ _feistel(R, k)

    # After 16 rounds the preoutput is R16 || L16 (swap then final permutation)
    return _permute((R << 32) | L, FP, 64)


def des_block_trace(
    block: int,
    round_keys: List[int],
    encrypt: bool = True,
) -> Dict[str, Any]:
    """

    Same as des_block() but also returns trace_summary and trace_full.
    Full trace captures L/R values at the start, end, and every 4 rounds
    (showing all 16 would be very long for large inputs)

    """
    direction = "ENCRYPT" if encrypt else "DECRYPT"
    trace_summary: List[str] = [
        f"DES {direction}: 16-round Feistel cipher on 64-bit block"
    ]
    trace_full: List[str] = [
        f"Input block:  {block:#018x}",
        f"Direction:    {direction}",
    ]

    after_ip = _permute(block, IP, 64)
    trace_full.append(f"After IP:     {after_ip:#018x}")

    L = (after_ip >> 32) & 0xFFFFFFFF
    R =  after_ip        & 0xFFFFFFFF
    trace_full.append(f"L0={L:#010x}  R0={R:#010x}")

    keys = round_keys if encrypt else list(reversed(round_keys))

    for i, k in enumerate(keys, start=1):
        L, R = R, L ^ _feistel(R, k)
        if i % 4 == 0 or i == 1:
            trace_full.append(f"Round {i:2d}: L={L:#010x}  R={R:#010x}")

    preoutput = (R << 32) | L
    result = _permute(preoutput, FP, 64)
    trace_full.append(f"Preoutput:    {preoutput:#018x}")
    trace_full.append(f"After FP:     {result:#018x}")

    trace_summary.append(f"Result: {result:#018x}")

    return {
        "result":        result,
        "trace_summary": trace_summary,
        "trace_full":    trace_full,
    }
