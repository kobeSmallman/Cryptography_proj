from cryptolab.crypto.math import gcd, egcd, modinv, modexp

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
    
