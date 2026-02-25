from __future__ import annotations

"""
Used by: RSA key generation, Diffie-Hellman key exchange, DES, signatures

Manual math implementations:
"""

from typing import List, Tuple

def gcd(a: int, b: int) -> int:
    """Greatest common divisor (Euclid)"""
    a = abs(a)
    b = abs(b)
    while b != 0:
        a, b = b, a % b
    return a

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended GCD (Euclid) returns (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1

    while r != 0:
        q = old_r // r # quotient to integer division
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
    
    return old_r, old_x, old_y

def egcd_trace(a: int, b: int) -> Tuple[int, int, int, List[str]]:
    """
    Same as egcd(), but also returna a list of steps and its used for FULL trace output.

    """
    steps: List[str] = []
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1

    while r != 0:
        q = old_r // r
        steps.append(f"q = old_r // r = {old_r} // {r} = {q}")
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
        steps.append(f"Update: old_r={old_r}, r={r}, old_x={old_x}, x={x}, old_y={old_y}, y={y}")

        steps.append(f"Done: gcd={old_r}, x={old_x}, y={old_y} (so a*x + b*y = gcd)")
        return old_r, old_x, old_y, steps
    
def modinv(a: int, m: int) -> int:
    """
    Modular inverse: find inv such that (a*inv) % m == 1
    Uses gcd(a, m)=1 and egcd to find the inverse
    """
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} mod {m} since gcd={g} != 1")
    return x % m

def modinv_trace(a: int, m: int) -> Tuple[int, List[str]]:
    """
    modinv() plus extended-euclid steps."""
    g, x, y, steps = egcd_trace(a, m)
    if g != 1:
        steps.append(f"Stop: gcd({g},{m})={g} so inverse does not exist")
        raise ValueError("No modular inverse exist")
    inv = x % m
    steps.append(f"Inverse = x mod m = {x} mod {m} = {inv}")
    return inv, steps

def modexp(base: int, exp: int, mod: int) -> int:
    """
    Modular exponentiation -> square and multiply and computes the base^exp mod mod efficiently.
    """
    if mod <= 0:
        raise ValueError("Modulus must be positive")
    if exp < 0:
        raise ValueError("Exponent must be non-negative")
    
    base %= mod
    result = 1

    while exp > 0:
        if exp & 1: # if exp is odd
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1 
    
    return result

def modexp_trace(base: int, exp: int, mod: int) -> Tuple[int, List[str]]:
    """
    modexp() plus steps"""
    steps: List[str] = []
    if mod <= 0:
        raise ValueError("mod must be positive")
    if exp < 0:
        raise ValueError("exp must be non-negative")
    
    base = base % mod
    result = 1
    steps.append(f"Start: base={base}, exp={exp}, mod={mod}, result={result}")

    bit_index = 0
    while exp > 0:
        bit = exp & 1
        steps.append(f"Bit {bit_index}: exp LSB={bit}") # 0 or 1
        if bit == 1: # if exp is odd, multiply result by current base
            result = (result * base) % mod
            steps.append(f"    results = (result*base) % mod = {result}")
        base = (base * base) % mod
        steps.append(f"   base = (base*base) % mod = {base}")
        exp >>= 1 # shift right to process next bit
        bit_index += 1
    
    steps.append(f"Done: result = {result}")
    return result, steps

def bit_length(n: int) -> int:
    return n.bit_length()

        

