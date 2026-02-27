from cryptolab.crypto.dh import dh_key_exchange

def test_dh_shared_secret_matches():
    r = dh_key_exchange(bits=64, mr_rounds=8, seed=12345)

    p = r["p"]
    g = r["g"]
    A = r["A"]
    B = r["B"]
    s = r["s"]

    assert 1 < g < p
    assert 0 <= A < p
    assert 0 <= B < p
    assert 0 <= s < p
