"""
DES key schedule: 64-bit key to list of 16 x 48-bit round keys.

Steps:
  1. PC-1 permutation: 64 bits to 56 bits (drops 8 parity bits)
  2. Split into two 28-bit halves C and D
  3. For each of 16 rounds, left-rotate C and D by the schedule amount
  4. PC-2 permutation on (C||D): 56 bits -> 48-bit round key
"""

from __future__ import annotations
from typing import List
from cryptolab.crypto.des.tables import PC1, PC2, SHIFT_SCHEDULE


def _permute(block: int, table: List[int], input_bits: int) -> int:
    """
    Apply a permutation table to an integer.
    table entries are 1-indexed bit positions from the MSB.
    """
    out = 0
    for bit_pos in table:
        out = (out << 1) | ((block >> (input_bits - bit_pos)) & 1)
    return out


def _left_rotate_28(val: int, n: int) -> int:
    """Left circular rotate a 28-bit value by n positions."""
    return ((val << n) | (val >> (28 - n))) & 0xFFFFFFF


def generate_round_keys(key_64: int) -> List[int]:
    """
    Generate 16 x 48-bit round keys from a 64-bit DES key.
    Returns a list of 16 integers, each fitting in 48 bits.
    """
    # Step 1: PC-1 strips parity bits: 64 -> 56 bits
    key_56 = _permute(key_64, PC1, 64)

    # Step 2: split into two 28-bit halves
    C = (key_56 >> 28) & 0xFFFFFFF
    D =  key_56        & 0xFFFFFFF

    round_keys: List[int] = []
    for i in range(16):
        # Step 3: rotate both halves
        C = _left_rotate_28(C, SHIFT_SCHEDULE[i])
        D = _left_rotate_28(D, SHIFT_SCHEDULE[i])

        # Step 4: PC-2 on the 56-bit concatenation -> 48-bit round key
        CD = (C << 28) | D
        round_keys.append(_permute(CD, PC2, 56))

    return round_keys
