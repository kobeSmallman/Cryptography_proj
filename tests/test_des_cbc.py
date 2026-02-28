from cryptolab.crypto.des.modes import (
    encrypt_cbc, decrypt_cbc,
    encrypt_cbc_trace, decrypt_cbc_trace,
)


def test_cbc_roundtrip_short():
    """A message shorter than one block must encrypt/decrypt properly"""
    key = b'\x13\x34\x57\x79\x9B\xBC\xDF\xF1'
    iv  = b'\x00' * 8
    msg = b'Hello!!'
    
    assert decrypt_cbc(encrypt_cbc(msg, key, iv), key, iv) == msg


def test_cbc_roundtrip_exact_block():
    """A message that is 8 bytes must survive."""
    key = b'\x13\x34\x57\x79\x9B\xBC\xDF\xF1'
    iv  = b'\x00' * 8
    msg = b'ABCDEFGH'

    assert decrypt_cbc(encrypt_cbc(msg, key, iv), key, iv) == msg


def test_cbc_roundtrip_multiblock():
    """A multi-block message must survive encrypt/decrypt."""
    key = b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
    iv  = b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'
    msg = b'This is a 32-byte test message!!'

    assert decrypt_cbc(encrypt_cbc(msg, key, iv), key, iv) == msg


def test_cbc_different_keys_differ():
    """Different keys must produce different ciphertexts for the same input."""
    msg  = b'Test message'
    iv   = b'\x00' * 8
    key1 = b'\x13\x34\x57\x79\x9B\xBC\xDF\xF1'
    key2 = b'\xFF\xEE\xDD\xCC\xBB\xAA\x99\x88'

    assert encrypt_cbc(msg, key1, iv) != encrypt_cbc(msg, key2, iv)


def test_cbc_different_ivs_differ():
    """Different IVs must produce different ciphertexts for the same input."""
    msg  = b'Test message'
    key  = b'\x13\x34\x57\x79\x9B\xBC\xDF\xF1'
    iv1  = b'\x00' * 8
    iv2  = b'\xFF' * 8

    assert encrypt_cbc(msg, key, iv1) != encrypt_cbc(msg, key, iv2)


def test_cbc_ciphertext_length():
    """Ciphertext length must be a multiple of 8 (block size)."""
    key = b'\x13\x34\x57\x79\x9B\xBC\xDF\xF1'
    iv  = b'\x00' * 8
    for n in (1, 7, 8, 9, 15, 16, 17):
        msg = bytes(range(n))
        ct = encrypt_cbc(msg, key, iv)
        assert len(ct) % 8 == 0, f"Ciphertext not block-aligned for input length {n}"


# ── trace variant tests ───────────────────────────────────────────────────────

_KEY = b'\x13\x34\x57\x79\x9B\xBC\xDF\xF1'
_IV  = b'\x00' * 8
_MSG = b'Hello, DES-CBC!'


def test_encrypt_cbc_trace_returns_trace_fields():
    """encrypt_cbc_trace must return non-empty trace_summary and trace_full."""
    r = encrypt_cbc_trace(_MSG, _KEY, _IV)
    assert isinstance(r["trace_summary"], list) and len(r["trace_summary"]) > 0
    assert isinstance(r["trace_full"],    list) and len(r["trace_full"])    > 0


def test_decrypt_cbc_trace_returns_trace_fields():
    """decrypt_cbc_trace must return non-empty trace_summary and trace_full."""
    ct = encrypt_cbc(_MSG, _KEY, _IV)
    r  = decrypt_cbc_trace(ct, _KEY, _IV)
    assert isinstance(r["trace_summary"], list) and len(r["trace_summary"]) > 0
    assert isinstance(r["trace_full"],    list) and len(r["trace_full"])    > 0


def test_encrypt_cbc_trace_ciphertext_matches_non_trace():
    """Trace variant must produce the same ciphertext as the plain variant."""
    r  = encrypt_cbc_trace(_MSG, _KEY, _IV)
    ct = encrypt_cbc(_MSG, _KEY, _IV)
    assert r["ciphertext"] == ct


def test_decrypt_cbc_trace_plaintext_matches_non_trace():
    """Trace variant must recover the same plaintext as the plain variant."""
    ct = encrypt_cbc(_MSG, _KEY, _IV)
    r  = decrypt_cbc_trace(ct, _KEY, _IV)
    pt = decrypt_cbc(ct, _KEY, _IV)
    assert r["plaintext"] == pt == _MSG


def test_encrypt_cbc_trace_full_mentions_blocks():
    """Full trace must contain at least one block-level line."""
    r = encrypt_cbc_trace(_MSG, _KEY, _IV)
    assert any("Block" in line for line in r["trace_full"])
