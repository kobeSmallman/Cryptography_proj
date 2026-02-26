from cryptolab.crypto.rsa import rsa_generate_keypair
from cryptolab.crypto.math import gcd, modexp

def test_rsa_keypair_properties_small():
    # Small bits for speed in tests
    r = rsa_generate_keypair(bits=64, mr_rounds=12, seed=999)

    p, q = r["p"], r["q"]
    n, phi_n = r["n"], r["phi_n"]
    e, d = r["e"], r["d"]

    assert p != q
    assert n == p * q
    assert phi_n == (p - 1) * (q - 1)
    assert (e * d) % phi_n == 1

    #RSA correctness: m -> c -> m
    m = 123456789
    if gcd(m, n) != 1:
        m = 98765431
    assert gcd(m, n) == 1

    c = modexp(m, e, n)
    m2 = modexp(c, d, n)
    assert m2 == m
    
