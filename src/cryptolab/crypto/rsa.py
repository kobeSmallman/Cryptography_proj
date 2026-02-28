from __future__ import annotations

"""
RSA (Rivest-Shamir-Adleman) key generation 
requirement 1.
Returns a dict with the following:
p, q, n, phi_n, e, d
p_bits, q_bits, n_bits
trace_summary: steps for summary mode
trace_full: deeper steps for full mode

"""

from typing import Any, Dict, List, Tuple

from cryptolab.crypto.math import gcd, modinv, modexp, modexp_trace, bit_length
from cryptolab.crypto.prng import XorShift64Star
from cryptolab.crypto.primes import generate_prime
from cryptolab.crypto.hash import sha256, sha256_trace

def _egcd_trace(a: int, b: int) -> Tuple[int, int, int, List[str]]:
    """
    Extended Euclid with step logging for the FULL trace and 
    returns (g, x, y, steps) where a*x + b*y are equal to g
    """
    steps: List[str] = []
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1

    steps.append(f"EGCD start: old_r={old_r}, r={r}, old_x={old_x}, x={x}, old_y={old_y}, y={y}")

    while r != 0:
        q = old_r // r 
        steps.append(f"q = {old_r} // {r} = {q}")

        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
        steps.append(f"Update: old_r={old_r}, r={r}, old_x={old_x}, x={x}, old_y={old_y}, y={y}")
    
    steps.append(f"EGCD done: gcd={old_r}, x={old_x}, y={old_y} (so a*x + b*y = gcd)")
    return old_r, old_x, old_y, steps

def rsa_generate_keypair(
    bits: int = 128, # default 128 bit primes are for fast demo and real RSA uses much higher values (1024 and 2048 bit modulus)
    mr_rounds: int = 24, # default is 24 rounds
    seed: int | None = None, # None for random seed
    e_default: int = 65537, # 65537 specifically because it is prime
) -> Dict[str, Any]:   
    """
    RSA keygen is done in this order:
    1. Generate p and q primes
    2) n = p*q
    3) phi_n = (p-1)*(q-1)
    4) Choose e with gcd(e, phi_n)=1 and try the e_default first
    5) d = e^-1 mod phi_n
    """
    rng = XorShift64Star(seed) # seed for repeatability
    trace_summary: List[str] = []
    trace_full: List[str] = []

    #1. generate primes:
    trace_summary.append("Step 1) Generate p and q primes using Miller-Rabin")

    p, p_sum, p_full = generate_prime(bits, mr_rounds, rng)
    q, q_sum, q_full = generate_prime(bits, mr_rounds, rng)

    #Avoid p == q because that would make phi_n == 0 and d would not exist
    while q == p:
        trace_summary.append("q matched p which is rare so generating q...")
        q, q_sum, q_full = generate_prime(bits, mr_rounds, rng)
    
    trace_summary.append(f"p generated (bit_length={p.bit_length()})")
    trace_summary.append(f"q generated (bit_length={q.bit_length()})")

    #FULL trace: include the successful candidate MR trace for p and q
    trace_full.append("PRIME p (successful candidate):")
    trace_full.extend(p_full)

    trace_full.append("PRIME q (successful candidate):")
    trace_full.extend(q_full)

    #2. compute n
    trace_summary.append("Step 2) Compute n = p*q")
    n = p * q
    trace_summary.append(f"n computed (bit_length={n.bit_length()})")

    #Step 3: compute phi_n
    trace_summary.append("Step 3) Compute phi_n = (p - 1) * (q - 1)")
    phi_n = (p - 1) * (q - 1)

    #Step 4: choose e
    trace_summary.append("Step 4) Choose e such that gcd(e, phi_n) = 1.")
    e = e_default

    if gcd(e, phi_n) != 1:
        trace_summary.append("Default e not valid for this phi_n. Choosing random odd e until valid")
        # pick a random odd e in [3, phi_n-1]
        while True:
            e = rng.randint(3, phi_n - 1) | 1 # ensure it's odd and has the top bit set to get the right bit length
            if gcd(e, phi_n) == 1:
                break
    trace_summary.append(f"Selected e = {e}")

    #Step 5: compute d
    trace_summary.append("Step 5) Compute d = e^-1 mod phi_n (mod inverse)")
    d = modinv(e, phi_n) #mod inverse so that (e*d) % phi_n == 1
    trace_summary.append("Computed d successfully (e*d mod phi_n = 1)")

    #FULL trace: showing EGCD steps for mod inverse reasoning
    g, x, y, egcd_steps = _egcd_trace(e, phi_n) #mod inverse so that (e*d) % phi_n == 1
    trace_full.append("MODULAR INVERSE (extended euclidean):")
    trace_full.extend(egcd_steps)
    trace_full.append(f"Check: gcd(e, phi_n) = {g} (must be 1)")
    trace_full.append(f"d = x mod phi_n = {x} mod {phi_n} = {d}")

    # Return values:
    return {
        "p": p,
        "q": q,
        "n": n,
        "phi_n": phi_n,
        "e": e,
        "d": d,
        "p_bits": bit_length(p),
        "q_bits": bit_length(q),
        "n_bits": bit_length(n),
        "trace_summary": trace_summary,
        "trace_full": trace_full,
    }


def rsa_encrypt(m: int, e: int, n: int) -> Dict[str, Any]:
    """
    Textbook RSA encryption: c = m^e mod n.

    m must satisfy 0 < m < n.
    Returns dict with 'c', 'trace_summary', 'trace_full'.
    """
    if not (0 < m < n):
        raise ValueError(f"Message m={m} must satisfy 0 < m < n={n}")

    trace_summary: List[str] = [
        "RSA ENCRYPT: c = m^e mod n",
        f"m (message) = {m}",
        f"e (public exponent) = {e}",
        f"n (modulus, bit_length={bit_length(n)}) = {n}",
    ]

    c, exp_steps = modexp_trace(m, e, n)

    trace_full: List[str] = list(trace_summary)
    trace_full.append("Modular exponentiation (square-and-multiply):")
    trace_full.extend(exp_steps)
    trace_full.append(f"c = {c}")

    trace_summary.append(f"c (ciphertext) = {c}")

    return {
        "c":             c,
        "trace_summary": trace_summary,
        "trace_full":    trace_full,
    }


def rsa_decrypt(c: int, d: int, n: int) -> Dict[str, Any]:
    """
    Textbook RSA decryption: m = c^d mod n.

    Returns dict with 'm', 'trace_summary', 'trace_full'.
    """
    if not (0 <= c < n):
        raise ValueError(f"Ciphertext c={c} must satisfy 0 <= c < n={n}")

    trace_summary: List[str] = [
        "RSA DECRYPT: m = c^d mod n",
        f"c (ciphertext) = {c}",
        f"d (private exponent) = {d}",
        f"n (modulus, bit_length={bit_length(n)}) = {n}",
    ]

    m, exp_steps = modexp_trace(c, d, n)

    trace_full: List[str] = list(trace_summary)
    trace_full.append("Modular exponentiation (square-and-multiply):")
    trace_full.extend(exp_steps)
    trace_full.append(f"m = {m}")

    trace_summary.append(f"m (message recovered) = {m}")

    return {
        "m":             m,
        "trace_summary": trace_summary,
        "trace_full":    trace_full,
    }


def rsa_sign(message: bytes, d: int, n: int) -> Dict[str, Any]:
    """
    RSA digital signature (Requirement 4).

    Steps:
      1. Hash the message with SHA-256 to get a fixed-size digest h.
      2. Reduce h mod n so it fits within the modulus.
      3. Sign: sig = h^d mod n  (only the private key holder can do this).
    """
    trace_summary: List[str] = []
    trace_full: List[str] = []

    # Step 1: hash the message
    trace_summary.append("Step 1) Hash the message using SHA-256")
    hash_result = sha256_trace(message)
    h = hash_result["digest"]
    trace_summary.append(f"SHA-256(message) = {hash_result['digest_hex']}")
    trace_full.append(f"message = {message!r}")
    trace_full.extend(hash_result["trace_full"])

    # Step 2: reduce h mod n so it fits the modulus
    # SHA-256 gives 256 bits but n might be smaller (e.g. 128-bit demo keys)
    trace_summary.append("Step 2) Reduce h mod n to fit the modulus")
    h_mod = h % n
    trace_summary.append(f"h mod n = {h_mod}")
    trace_full.append(f"h mod n = {h_mod}")

    # Step 3: sign with the private exponent d
    trace_summary.append("Step 3) Sign: sig = h^d mod n (modular exponentiation)")
    sig, exp_steps = modexp_trace(h_mod, d, n)
    trace_full.extend(exp_steps)
    trace_full.append(f"sig = {sig}")
    trace_summary.append(f"sig = {sig}")

    return {
        "sig":           sig,
        "h":             h,          # full 256-bit digest (integer)
        "h_mod":         h_mod,      # digest reduced mod n (what actually gets signed)
        "trace_summary": trace_summary,
        "trace_full":    trace_full,
    }


def rsa_verify(message: bytes, sig: int, e: int, n: int) -> Dict[str, Any]:
    """
    RSA signature verification (Requirement 4).

    Steps:
      1. Hash the message with SHA-256 to get the expected digest h.
      2. Recover h' from the signature: h' = sig^e mod n (public key).
      3. Compare: if h' == h mod n the signature is valid.
    """
    if not (0 <= sig < n):
        raise ValueError("sig must satisfy 0 <= sig < n")

    trace_summary: List[str] = []
    trace_full: List[str] = []

    # Step 1: hash the message the same way the signer did
    trace_summary.append("Step 1) Hash the message using SHA-256 (same as signer)")
    hash_result = sha256_trace(message)
    h = hash_result["digest"]
    h_mod = h % n
    trace_summary.append(f"SHA-256(message) = {hash_result['digest_hex']}")
    trace_summary.append(f"h mod n = {h_mod}")
    trace_full.append(f"message = {message!r}")
    trace_full.extend(hash_result["trace_full"])
    trace_full.append(f"h mod n = {h_mod}")

    # Step 2: recover the digest from the signature using the public exponent e
    trace_summary.append("Step 2) Recover hash: h' = sig^e mod n (modular exponentiation)")
    trace_full.append(f"sig = {sig}")
    h_recovered, exp_steps = modexp_trace(sig, e, n)
    trace_full.extend(exp_steps)
    trace_full.append(f"h' (recovered) = {h_recovered}")

    # Step 3: compare recovered digest with expected
    valid = (h_mod == h_recovered)
    trace_summary.append(f"Step 3) Compare h' == h mod n -> {h_mod} == {h_recovered}")
    trace_summary.append(f"Signature {'VALID' if valid else 'INVALID'}")
    trace_full.append(f"h mod n        = {h_mod}")
    trace_full.append(f"h' (recovered) = {h_recovered}")
    trace_full.append(f"Match: {valid} => signature is {'VALID' if valid else 'INVALID'}")

    return {
        "valid":         valid,
        "h_mod":         h_mod,        # expected digest
        "h_recovered":   h_recovered,  # digest from signature
        "trace_summary": trace_summary,
        "trace_full":    trace_full,
    }
