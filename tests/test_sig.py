from cryptolab.crypto.rsa import rsa_generate_keypair, rsa_sign, rsa_verify


def _keypair():
    """Small 64-bit key — just fast enough for testing."""
    return rsa_generate_keypair(bits=64, mr_rounds=12, seed=42)


def test_sign_verify_valid():
    """A freshly signed message should verify correctly."""
    keys   = _keypair()
    msg    = b"Hello, world!"
    signed = rsa_sign(msg, keys["d"], keys["n"])
    result = rsa_verify(msg, signed["sig"], keys["e"], keys["n"])
    assert result["valid"] is True


def test_verify_fails_changed_message():
    """Verifying with a different message than what was signed should fail."""
    keys   = _keypair()
    signed = rsa_sign(b"original message", keys["d"], keys["n"])
    result = rsa_verify(b"tampered message", signed["sig"], keys["e"], keys["n"])
    assert result["valid"] is False


def test_verify_fails_changed_signature():
    """Flipping even one bit of the signature should fail verify."""
    keys    = _keypair()
    msg     = b"signed message"
    signed  = rsa_sign(msg, keys["d"], keys["n"])
    bad_sig = signed["sig"] ^ 1  # flip the lowest bit
    result  = rsa_verify(msg, bad_sig, keys["e"], keys["n"])
    assert result["valid"] is False


def test_sign_returns_trace_fields():
    """rsa_sign must return non-empty trace_summary and trace_full."""
    keys   = _keypair()
    signed = rsa_sign(b"trace check", keys["d"], keys["n"])
    assert isinstance(signed["trace_summary"], list) and len(signed["trace_summary"]) > 0
    assert isinstance(signed["trace_full"],    list) and len(signed["trace_full"])    > 0


def test_verify_returns_trace_fields():
    """rsa_verify must return non-empty trace_summary and trace_full."""
    keys   = _keypair()
    msg    = b"trace verify"
    signed = rsa_sign(msg, keys["d"], keys["n"])
    result = rsa_verify(msg, signed["sig"], keys["e"], keys["n"])
    assert isinstance(result["trace_summary"], list) and len(result["trace_summary"]) > 0
    assert isinstance(result["trace_full"],    list) and len(result["trace_full"])    > 0


def test_sign_result_contains_hash():
    """The sign result should expose the SHA-256 digest h as an integer."""
    keys   = _keypair()
    signed = rsa_sign(b"hash check", keys["d"], keys["n"])
    assert "h" in signed
    assert isinstance(signed["h"], int)


def test_verify_exposes_recovered_hash():
    """On a valid signature h_mod and h_recovered must be the same value"""
    keys   = _keypair()
    msg    = b"recovery check"
    signed = rsa_sign(msg, keys["d"], keys["n"])
    result = rsa_verify(msg, signed["sig"], keys["e"], keys["n"])
    assert result["h_mod"] == result["h_recovered"]


def test_multiple_messages_sign_verify():
    """Sign and verify several messages with the same key pair"""
    keys     = _keypair()
    messages = (b"a", b"short", b"a longer message for testing purposes")
    for msg in messages:
        signed = rsa_sign(msg, keys["d"], keys["n"])
        result = rsa_verify(msg, signed["sig"], keys["e"], keys["n"])
        assert result["valid"] is True, f"Failed for msg={msg!r}"
