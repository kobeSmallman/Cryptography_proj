from __future__ import annotations

"""
Manual SHA-256 implementation — Requirement 4 (digital signatures)
No hashlib or any external library is used anywhere in this file

How SHA-256 works (big picture):
  1. Pad the message so its length is a multiple of 512 bits (64 bytes)
  2. Break the padded message into 64-byte blocks
  3. Run each block through a 64-round compression function that mixes
     the block into an 8-word (256-bit) running hash state
  4. The final hash state is the digest

Used here as: h = SHA-256(message), then sig = h^d mod n for signing
"""

from typing import Any, Dict, List


# ── constants ─────────────────────────────────────────────────────────────────
# These are fixed by the SHA-256 standard (FIPS 180-4).

# Starting hash values — first 32 bits of the fractional parts of sqrt(2), sqrt(3), ..., sqrt(19)
_H0: List[int] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

# Round constants — first 32 bits of the fractional parts of cbrt of the first 64 primes
_K: List[int] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08,  0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# All SHA-256 arithmetic is done modulo 2^32 (32-bit words)
_MASK32 = 0xFFFFFFFF


# ── helpers ───────────────────────────────────────────────────────────────────

def _rotr(x: int, n: int) -> int:
    """Right-rotate a 32-bit integer x by n positions"""
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _pad(data: bytes) -> bytes:
    """
    Pad the message so its length in bytes is a multiple of 64 (512 bits)

    SHA-256 padding steps:
      1. Append a single 0x80 byte (the '1' bit in bit-level terms)
      2. Append 0x00 bytes until the total length is 56 mod 64
         (leaving 8 bytes at the end for the length field)
      3. Append the original message length in bits as a big-endian 64-bit int
    """
    bit_len = len(data) * 8  # original message length in bits

    # Step 1: append the 1 bit (as a full 0x80 byte)
    data += b"\x80"

    # Step 2: pad with zeros until we have 56 bytes in the current block
    while len(data) % 64 != 56:
        data += b"\x00"

    # Step 3: append the 64-bit big-endian bit length
    data += bit_len.to_bytes(8, "big")

    return data


def _compress(block: bytes, h: List[int]) -> List[int]:
    """
    Run one 64-byte block 

    This is the core of SHA-256. It takes the current hash state (8 words)
    and mixes in one 512-bit message block over 64

    Steps:
      one. Build the message schedule W[0..63]
         W[0..15] come directly from the block
         W[16..63] are derived using sigma functions (mixing previous words)
      two. Copy the current hash state into working variables a..h
      three. Run 64 rounds — each round mixes one W[i] and one K[i] into the state
      four. Add the round output back to original state
    """

    # Step 1: build the message schedule
    w: List[int] = []

    # First 16 words come straight
    for i in range(0, 64, 4):
        w.append(int.from_bytes(block[i : i + 4], "big"))

    # Words 16..63 are computed using
    for i in range(16, 64):
        # sigma0: ROTR7 XOR ROTR18 XOR SHR3 applied to w[i-15]
        sigma0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        # sigma1: ROTR17 XOR ROTR19 XOR SHR10 applied to w[i-2]
        sigma1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + sigma0 + w[i - 7] + sigma1) & _MASK32)

    # Step 2: set working variables a..h to the current hash values
    a, b, c, d, e, f, g, hh = h

    # Step 3: 64 rounds of mixing
    for i in range(64):
        # Sigma1: rotation mix on e
        big_sigma1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)

        # Ch (choice): if e's bit is 1 pick f, else pick g
        ch = (e & f) ^ ((e ^ _MASK32) & g)  # (e ^ _MASK32) = 32-bit NOT of e

        # t1 combines the current h, mixing functions, round constant, and message word
        t1 = (hh + big_sigma1 + ch + _K[i] + w[i]) & _MASK32

        # Sigma0: rotation mix on a
        big_sigma0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)

        # Maj (majority): picks the value that at least 2 of a, b, c agree on
        maj = (a & b) ^ (a & c) ^ (b & c)

        # t2 combines the Sigma0 and majority functions
        t2 = (big_sigma0 + maj) & _MASK32

        # Rotate the working variables down one position and set the new values
        hh, g, f = g, f, e         # h=g, g=f, f=e
        e = (d + t1) & _MASK32     # new e = old d + t1
        d, c, b = c, b, a          # d=c, c=b, b=a
        a = (t1 + t2) & _MASK32    # new a = t1 + t2

    # Step 4: add the working variables back to the hash state
    return [
        (h[0] + a)  & _MASK32,
        (h[1] + b)  & _MASK32,
        (h[2] + c)  & _MASK32,
        (h[3] + d)  & _MASK32,
        (h[4] + e)  & _MASK32,
        (h[5] + f)  & _MASK32,
        (h[6] + g)  & _MASK32,
        (h[7] + hh) & _MASK32,
    ]


# ── public API ────────────────────────────────────────────────────────────────

def sha256(data: bytes) -> int:
    """
    Compute SHA-256 of data and return the 256-bit digest as an integer

    Steps:
      one. Pad the message
      two. Process each 64-byte block through the compression function
      three. Assemble the 8 output words into one 256-bit integer
    """
    # Step 1: pad
    padded = _pad(data)

    # Step 2: process each block, updating the hash state h
    h = list(_H0)
    for i in range(0, len(padded), 64):
        h = _compress(padded[i : i + 64], h)

    # Step 3: pack the 8 words into a single big integer (most-significant word first)
    digest = 0
    for word in h:
        digest = (digest << 32) | word

    return digest


def sha256_hex(data: bytes) -> str:
    """Returns SHA-256(data) as a lowercase 64-character hex string"""
    return f"{sha256(data):064x}"


def sha256_trace(data: bytes) -> Dict[str, Any]:
    """

    Same as sha256() but also returns trace_summary and trace_full lists
    so the UI can show what happened step by step.

    """

    padded   = _pad(data)
    n_blocks = len(padded) // 64


    trace_summary: List[str] = [
        f"SHA-256 input: {len(data)} byte(s) -> {n_blocks} block(s) after padding",
        "Padding: append 0x80, zeros until length = 56 mod 64, then 8-byte bit-length",
    ]
    
    trace_full: List[str] = list(trace_summary)
    trace_full.append(f"Padded message (hex): {padded.hex()}")
    trace_full.append(f"Starting H[0..7]:     {' '.join(f'{x:08x}' for x in _H0)}")

    # Process each block and record the state after each one
    h = list(_H0)
    for blk_idx in range(n_blocks):
        block = padded[blk_idx * 64 : blk_idx * 64 + 64]

        # Show the first 4 words of the message schedule for this block
        first_four = [int.from_bytes(block[i : i + 4], "big") for i in range(0, 16, 4)]
        trace_full.append(
            f"Block {blk_idx} W[0..3]: {' '.join(f'{x:08x}' for x in first_four)}"
        )

        h = _compress(block, h)

        trace_full.append(
            f"Block {blk_idx} H[0..7] after compress: {' '.join(f'{x:08x}' for x in h)}"
        )
        

    # Assemble the final digest
    digest = 0
    for word in h:
        digest = (digest << 32) | word
    digest_hex = f"{digest:064x}"

    trace_summary.append(f"SHA-256 digest: {digest_hex}")
    trace_full.append(f"Final digest: {digest_hex}")

    return {
        "digest":        digest,
        "digest_hex":    digest_hex,
        "trace_summary": trace_summary,
        "trace_full":    trace_full,
    }
