from __future__ import annotations

"""
Diffie-Hellman key exchange Requirement#2
Goal: 
Two parties agree on public parameter (p, g)
then each chooses a private exponent (a, b)
then they exchange public value (A, B)
finally they independently compute the same shared secret :)

Formulas used:
A = g^a mod p
B = g^b mod p
s_alice = B^a mod p
s_bob = A^b mod p
Shared secret s = s_alice = s_bob
"""

from typing import Any, Dict, List, Tuple

from cryptolab.crypto.math import modexp, gcd, bit_length
from cryptolab.crypto.prng import XorShift64Star
from cryptolab.crypto.primes import generate_prime, is_probable_prime

def _small_factors(n: int, limit: int = 2000) -> List[int]:
    """
    Division for small prime factors of n 
    (used to check g) and this doesn't FULLY 
    factor large n but it's practical
    """
    factors: List[int] = []
    x = n
    d = 2 # start at 2 because we don't want to divide by 1 obviously
    while d * d <= x and d <= limit:
        if x % d == 0: # found a factor
            factors.append(d)
            while x % d == 0:
                x//= d
        d = 3 if d == 2 else d + 2 # next odd divisor
    return factors

def _pick_reasonable_g(p: int) -> int:
    """
    Pick a reasonable base g that avoids obvious bad choices and we try g = 2..50 and reject values
    that fail basic checks against small factors of p - 1.
    Doesn't guarantee a primitive root because that would require a full factorization of p - 1 but it's decent
    """
    phi = p -1
    small = _small_factors(phi)

    for g in range(2, 51):
        if g >= p:
            continue
        if gcd(g, p) != 1:
            continue

        # for each small factor q of p - 1 require that g^((p-1)/q) != 1 mod p
        # sanity check
        ok = True
        for q in small:
            if modexp(g, phi // q, p) == 1:
                ok = False
                break
        if ok:
            return g
    
    #fallback
    return 2

def dh_key_exchange(
        bits: int = 128, # default 128 bit primes are for fast demo and real RSA uses much higher values (1024 and 2048 bit modulus)
        mr_rounds: int = 24, # default is 24 rounds
        seed: int | None = None, # None for random seed
        p_override: int | None = None, # override prime
        g_override: int | None = None # override base
    ) -> Dict[str, Any]:
    
    rng = XorShift64Star(seed) # seed for repeatability

    
    trace_summary: List[str] = []
    trace_full: List[str] = []

    # Pick p
    if p_override is None:
        trace_summary.append("step 1) Generate prime p (public) using Miller-Rabbin")
        p, p_sum, p_full = generate_prime(bits, mr_rounds, rng)
        trace_full.append("PRIME p (successful cnadidate):")
        trace_full.extend(p_full)
    else:
        p = p_override
        ok, s_trace, f_trace = is_probable_prime(p, rounds=mr_rounds, rng=rng)
        trace_summary.append("Step 1) Use provided p (public) and check if it is a probable prime")
        trace_full.append("Provided p primality check:")
        trace_full.extend(f_trace)
        if not ok:
            raise ValueError("Provided p is not a prime")
    
    # step 2 pick g
    trace_summary.append("step 2) Pick a base g (public).")
    if g_override is None:
        g = _pick_reasonable_g(p)
        trace_summary.append(f"Using g={g} (sanity check against small factors of p-1)")
    else:
        g = g_override
        trace_summary.append(f"Using provided g={g}")
    
    if not (1< g < p):
        raise ValueError("g is not in range 1..p-1")
    
    #step 3 choose secrets a and b
    trace_summary.append("Step 3) Choose secret exponents a and b")
    a = rng.randint(2, p -2) # a must be in range 2..p-2
    b = rng.randint(2, p -2) # b must be in range 2..p-2
    trace_full.append(f"Secret a chosen (FULL only): a={a}")
    trace_full.append(f"Secret b chosen (FULL only): b={b}")

    #step 4: Compute public values A and B
    trace_summary.append("step 4) Compute public values A=g^a mod p and B=g^b mod p")
    A = modexp(g, a, p)
    B = modexp(g, b, p)
    trace_summary.append("Computed A and B")
    trace_full.append(f"A = g^a mod p (FULL only): A={A}")
    trace_full.append(f"B = g^b mod p (FULL only): B={B}")

    #step 5: compute shared secret s two ways
    trace_summary.append("step 5) Compute shared secret s two ways and verify they match")
    s_alice = modexp(B, a, p)
    s_bob = modexp(A, b, p)
    trace_full.append(f"s_alice = B^a mod p = {s_alice}")
    trace_full.append(f"s_bob = A^b mod p = {s_bob}")

    if s_alice != s_bob:
        raise RuntimeError("DH failed: s_alice != s_bob  but this should never happen if everything is correct")
    
    s = s_alice
    trace_summary.append("Verified: s_alice == s_bob (shared secret was.... ESTABLISHED!)")

    return{
        "p": p,
        "g": g,
        "a": a,
        "b": b,
        "A": A,
        "B": B,
        "s": s,
        "p_bits": bit_length(p),
        "trace_summary": trace_summary,
        "trace_full": trace_full
    }

    