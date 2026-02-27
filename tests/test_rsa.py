from cryptolab.crypto.rsa import rsa_generate_keypair
from cryptolab.crypto.math import gcd, modexp


def test_rsa_keypair_properties_small():
    r = rsa_generate_keypair(bits=64, mr_rounds=12, seed=999)

    p, q = r["p"], r["q"]
    n, phi_n = r["n"], r["phi_n"]
    e, d = r["e"], r["d"]

    assert p != q
    assert n == p * q
    assert phi_n == (p - 1) * (q - 1)
    assert (e * d) % phi_n == 1

    m = 123456789
    if gcd(m, n) != 1:
        m = 98765431
    assert gcd(m, n) == 1

    c = modexp(m, e, n)
    assert modexp(c, d, n) == m


def test_rsa_keypair_multiple_seeds():
    """Key generation must produce valid keypairs for several different seeds."""
    for seed in (1, 42, 1337, 999999):
        r = rsa_generate_keypair(bits=64, mr_rounds=12, seed=seed)
        assert r["p"] != r["q"]
        assert r["n"] == r["p"] * r["q"]
        assert r["phi_n"] == (r["p"] - 1) * (r["q"] - 1)
        assert (r["e"] * r["d"]) % r["phi_n"] == 1


def test_rsa_encrypt_decrypt_multiple_messages():
    """Encrypt then decrypt must recover the original message for various values of m."""
    r = rsa_generate_keypair(bits=64, mr_rounds=12, seed=2024)
    n, e, d = r["n"], r["e"], r["d"]

    candidates = [2, 100, 65537, 999999, n - 2]
    tested = 0
    for m in candidates:
        if m <= 1 or m >= n or gcd(m, n) != 1:
            continue
        c = modexp(m, e, n)
        assert modexp(c, d, n) == m, f"Round-trip failed for m={m}"
        tested += 1
    assert tested >= 3, "Too few valid test messages; check n size"


def test_rsa_n_bit_length():
    """n must be approximately 2*bits bits wide (127 or 128 for bits=64)."""
    r = rsa_generate_keypair(bits=64, mr_rounds=12, seed=77)
    assert 126 <= r["n_bits"] <= 129, f"Unexpected n bit length: {r['n_bits']}"


def test_rsa_trace_fields_present():
    """Result dict must contain both trace_summary and trace_full as non-empty lists."""
    r = rsa_generate_keypair(bits=64, mr_rounds=12, seed=5)
    assert isinstance(r["trace_summary"], list) and len(r["trace_summary"]) > 0
    assert isinstance(r["trace_full"], list) and len(r["trace_full"]) > 0

