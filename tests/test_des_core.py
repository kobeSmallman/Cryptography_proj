from cryptolab.crypto.des.key_schedule import generate_round_keys
from cryptolab.crypto.des.core import des_block

# DES worked example (J. Orlin Grabbe / FIPS PUB 46)
_KEY       = 0x133457799BBCDFF1
_PLAINTEXT = 0x0123456789ABCDEF
_CIPHERTEXT = 0x85E813540F0AB405


def test_key_schedule_produces_16_keys():
    """Key schedule must return 16 rounds"""
    keys = generate_round_keys(_KEY)
    assert len(keys) == 16


def test_key_schedule_keys_are_48bit():
    """Every round key must be within 48 bits."""

    keys = generate_round_keys(_KEY)
    for i, k in enumerate(keys):
        assert 0 <= k < (1 << 48), f"Round key {i} out of 48-bit range: {k}"


def test_des_known_vector_encrypt():
    """Encrypting the standard test plaintext must produce th ciphertext"""
    keys = generate_round_keys(_KEY)
    result = des_block(_PLAINTEXT, keys, encrypt=True)
    assert result == _CIPHERTEXT, (
        f"Expected {_CIPHERTEXT:#018x}, got {result:#018x}"
    )


def test_des_known_vector_decrypt():
    """Decrypting the known ciphertext must recover the plaintext example"""
    keys = generate_round_keys(_KEY)
    result = des_block(_CIPHERTEXT, keys, encrypt=False)
    assert result == _PLAINTEXT, (
        f"Expected {_PLAINTEXT:#018x}, got {result:#018x}"
    )


def test_des_encrypt_decrypt_roundtrip():
    """Encrypt-then-decrypt must return the original block for several inputs"""
    keys = generate_round_keys(_KEY)

    for block in (0x0000000000000000, 0xFFFFFFFFFFFFFFFF,
                  0xDEADBEEFCAFEBABE, 0x0123456789ABCDEF):

        ct = des_block(block, keys, encrypt=True)
        pt = des_block(ct,    keys, encrypt=False)
        assert pt == block, f"Round-trip failed for block {block:#018x}"


def test_des_different_keys_produce_different_ciphertext():
    """Two different keys must produce different ciphertexts."""
    keys1 = generate_round_keys(0x133457799BBCDFF1)
    keys2 = generate_round_keys(0xAABBCCDDEEFF0011)


    pt = 0x0123456789ABCDEF
    assert des_block(pt, keys1, encrypt=True) != des_block(pt, keys2, encrypt=True)
