from cryptolab.crypto.prng import XorShift64Star


def test_xorshift_reproducible():
    """The same seed same output sequence"""
    rng1 = XorShift64Star(123)
    rng2 = XorShift64Star(123)
    for _ in range(20):
        assert rng1.next_u64() == rng2.next_u64()


def test_xorshift_different_seeds_differ():
    """Different seeds diff outputs sequences"""
    rng1 = XorShift64Star(1)
    rng2 = XorShift64Star(2)
    outputs1 = [rng1.next_u64() for _ in range(10)]
    outputs2 = [rng2.next_u64() for _ in range(10)]
    assert outputs1 != outputs2


def test_xorshift_output_64bit():
    """next_u64 must return a value in [0 , 2 ^ 64 - 1]."""
    rng = XorShift64Star(55)
    for _ in range(50):
        val = rng.next_u64()
        assert 0 <= val < (1 << 64)


def test_xorshift_randbits_range():
    """randbits(k) must return a value in [0, 2^k - 1]."""
    rng = XorShift64Star(55)
    for k in (8, 16, 32, 64, 128):
        val = rng.randbits(k)
        assert 0 <= val < (1 << k), f"randbits({k}) returned out-of-range value {val}"


def test_xorshift_randint_bounds():
    """randint(a, b) must  return a value in [a, b]."""
    rng = XorShift64Star(77)
    for _ in range(200):
        val = rng.randint(10, 20)
        assert 10 <= val <= 20, f"randint(10, 20) returned {val}"


def test_xorshift_zero_seed_avoided():
    """A seed of 0 must not produce an all-zero state"""
    rng = XorShift64Star(0)
    assert rng.state != 0
    assert rng.next_u64() != 0
