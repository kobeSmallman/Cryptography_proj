from cryptolab.crypto.hash import sha256, sha256_hex, sha256_trace

# SHA-256 test vectors verified against the NIST SHA examples document
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
_VECTORS = [
    (b"",      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc",   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"hello", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
    # this one is 55 bytes which forces a second 512-bit padding block
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
]





def test_sha256_returns_int():
    """sha256() should return a plain Python integer"""
    result = sha256(b"test")
    assert isinstance(result, int)
    assert result > 0

def test_sha256_known_vectors():
    """Check our SHA-256 against every NIST test vector"""
    for data, expected in _VECTORS:
        assert sha256_hex(data) == expected, f"Wrong digest for input {data!r}"

def test_sha256_output_is_256_bits():
    """Digest must never exceed 256 bits"""
    for data, _ in _VECTORS:
        assert sha256(data).bit_length() <= 256

def test_sha256_deterministic():
    """Same input must always give the same output."""
    assert sha256(b"repeat") == sha256(b"repeat")

def test_sha256_different_inputs_differ():
    """Two different messages should produce different digest"""
    assert sha256(b"foo") != sha256(b"bar")
    assert sha256(b"") != sha256(b"a")

def test_sha256_trace_digest_matches():
    """The trace variant must compute the same digest as the plain function"""
    for data, expected in _VECTORS:
        result = sha256_trace(data)
        assert result["digest_hex"] == expected
        assert result["digest"] == sha256(data)

def test_sha256_trace_fields_present():
    """Trace result must include non-empty trace_summary and trace_full lists"""
    result = sha256_trace(b"trace test")
    assert isinstance(result["trace_summary"], list) and len(result["trace_summary"]) > 0
    assert isinstance(result["trace_full"],    list) and len(result["trace_full"])    > 0
