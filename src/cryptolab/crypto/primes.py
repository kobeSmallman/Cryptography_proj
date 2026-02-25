from __future__ import annotations

"""
Prime testing and prime generation (Miller-Rabin)
Desgin is:
Produces trace strings so UI can show intermediate steps
keeps FULL trace to be somwewhat reasonable and not like a million lines for big numbers, but still show the key steps and values.
"""

from typing import List, Tuple

from cryptolab.crypto.math import gcd, modexp
from cryptolab.crypto.prng import XorShift64Star


def is_probable_prime(n: int, rounds: int, rng: XorShift64Star) -> Tuple[bool, List[str], List[str]]:
    """
    Miller-Rabin primality test with trace output.
    """
    summary: List[str] = []
    full: List[str] = []

    #rejects and accepts
    if n < 2:
        summary.append("n < 2 => composite") # too small to be interesting and more likely to have false positives with few rounds
        full.append("n < 2 => composite")
        return False, summary, full
    if n in (2, 3):
        summary.append("n is 2 or 3 => prime")
        full.append("n is 2 or 3 => prime")
        return True, summary, full

    if n % 2 == 0:
        summary.append("n is even => composite")
        full.append("n is even => composite")
        return False, summary, full

   
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    
    summary.append(f"Decompose: n-1 = d * 2^s with d odd (s={s})")
    full.append(f"n={n}")
    full.append(f"n-1={n-1} => d={d}, s={s}")

    #Miller-Rabin rounds:
    for i in range(rounds):
        a = rng.randint(2, n -2) # random base in [2, n-2]

        if gcd(a, n) != 1:
            summary.append(f"Round {i+1}: gcd(a, n) != 1 => composite")
            full.append(f"Round {i+1}: a={a}, gcd(a, n)!=1 => composite")
            return False, summary, full
        
        x = modexp(a, d, n) # compute a^d mod n
        full.append(f"Round {i+1}: choose a={a}, compute x=a^d mod n => x={x}")

        if x == 1 or x == n - 1:
            full.append("   x is 1 or n-1 +> round passes")
            continue # this round passes, test next round

        #square x up to s-1 times
        witness = True # assume composite until we find a witness that shows it's probably prime by hitting n-1
        for r in range(s - 1):
            x = (x * x) % n
            full.append(f"  square {r+1}: x = x^2 mod n => x={x}")
            if x == n - 1:
                witness = False
                full.append("  hit n-1 => round passes")
                break

        if witness:
            summary.append(f"Round {i+1}: witness found => composite")
            full.append("  witness found => composite")
            return False, summary, full
    summary.append(f"Passed {rounds} rounds => probable prime")
    full.append(f"Passed {rounds} rounds => probable prime")
    return True, summary, full

def generate_prime(bits: int, rounds: int, rng: XorShift64Star) -> Tuple[int, List[str], List[str]]:
    """
    Generate a prime number approximately 'bits' bits long using Miller-Rabin for testing.
    returns: prime, summary_trace, full_trace
 
       """
    if bits < 16:
        raise ValueError("bits must be >= 16 because it's too small and could lead to false positives") # too small to be interesting and more likely to have false positives with few rounds
    
    summary: List[str] = [f"Generate prime: target bits={bits}"]
    full: List[str] = []

    attempts = 0
    while True:
        attempts += 1

        # random odd number with top bit set
        candidate = rng.randbits(bits) | (1 << (bits - 1)) | 1 # ensure it's odd and has the top bit set to get the right bit length

        ok, s_trace, f_trace = is_probable_prime(candidate, rounds, rng)

        #keep summary readable
        if attempts == 1:
            summary.append("try candidates until one passes Miller-Rabin test")

        if ok:
            summary.append(f"Prime found after {attempts} attempt(s). bit_length={candidate.bit_length()}")
            # For FULL: show only the successful candidate's MR trace to avoid an insane output
            full.append(f"Successful candidate: {candidate}")
            full.extend(f_trace)
            return candidate, summary, full
