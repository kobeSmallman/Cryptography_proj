from cryptolab.crypto.kdf import derive_des_key_iv


def test_kdf_produces_8_byte_key_and_iv():
    """key and iv must both be exactly 8 bytes (DES block size)"""

    r = derive_des_key_iv(123456789)
    assert isinstance(r["key"], bytes) and len(r["key"]) == 8
    assert isinstance(r["iv"],  bytes) and len(r["iv"])  == 8

def test_kdf_deterministic():
    """Same shared secret must always produce the same key and iv"""
    s = 99999999999999999999
    
    r1 = derive_des_key_iv(s)
    r2 = derive_des_key_iv(s)

    assert r1["key"] == r2["key"]
    assert r1["iv"]  == r2["iv"]


def test_kdf_different_secrets_produce_different_keys():
    """Different shared secrets must produce differenty keys"""
    r1 = derive_des_key_iv(111111111111)
    r2 = derive_des_key_iv(222222222222)
    assert r1["key"] != r2["key"] or r1["iv"] != r2["iv"]


def test_kdf_key_and_iv_are_different():
    """key and iv derived from the same secret must differ"""
    r = derive_des_key_iv(42)
    assert r["key"] != r["iv"]


def test_kdf_trace_fields_present():

    """contain non-empty trace_summary and trace_full lists"""
    r = derive_des_key_iv(314159265358979)
    assert isinstance(r["trace_summary"], list) and len(r["trace_summary"]) > 0
    assert isinstance(r["trace_full"],    list) and len(r["trace_full"])    > 0


def test_kdf_large_secret():
    """handle a very large shared secret """
    large_s = 2**256 + 2**128 + 7
    r = derive_des_key_iv(large_s)
    assert len(r["key"]) == 8
    assert len(r["iv"])  == 8

def test_kdf_single_byte_secret():
    r = derive_des_key_iv(1)
    assert len(r["key"]) == 8
    assert len(r["iv"])  == 8
