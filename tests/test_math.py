from cryptolab.crypto.math import gcd, egcd, egcd_trace, modinv, modinv_trace, modexp

def test_gcd():
    assert gcd(54, 24) == 6 # 54 = 6 * 9 = 24 * 3
    assert gcd(17, 13) == 1 # 17 = 1 * 17 = 13 * 1
    assert gcd(-10, 5) == 5 # -10 = 5 * -2 = 5 * 2


def test_egcd_identity():
    g, x, y = egcd(240, 46)
    assert g == 2
    assert 240 * x + 46 * y == g

def test_modinv():
    assert modinv(3, 11) == 4 # 3 * 4= 12= 1 mod 11

def test_modexp():
    assert modexp(2, 10, 1000) == 24
    assert modexp(5, 0, 7) == 1
def test_egcd_trace_matches_egcd():
    """egcd trace return same (g, x, y) as egcd and correct a * x + b * y = gcd(a, b)"""
    pairs = [(240, 46), (35, 15), (17, 13), (100, 75), (3, 11)]
    for a, b in pairs:
        g_ref, x_ref, y_ref = egcd(a, b)
        g, x, y, steps = egcd_trace(a, b)
        assert g == g_ref, f"gcd mismatch for ({a},{b}): got {g}, expected {g_ref}"
        assert x == x_ref, f"x mismatch for ({a},{b}): got {x}, expected {x_ref}"
        assert y == y_ref, f"y mismatch for ({a},{b}): got {y}, expected {y_ref}"
        assert a * x + b * y == g, f"Bezout identity failed for ({a},{b})"
        assert isinstance(steps, list) and len(steps) > 0

def test_modinv_trace_correctness():
    """modinv_trace return the same inverse as modinv and (a * inv) % m == 1"""
    pairs = [(3, 11), (7, 26), (13, 120)]
    for a, m in pairs:
        inv_ref = modinv(a, m)
        inv, steps = modinv_trace(a, m)
        assert inv == inv_ref, f"modinv_trace mismatch for ({a},{m}): got {inv}, expected {inv_ref}"
        assert (a * inv) % m == 1, f"Inverse property failed for ({a},{m})"
        assert isinstance(steps, list) and len(steps) > 0

