from cryptolab.crypto.prng import XorShift64Star
from cryptolab.crypto.primes import is_probable_prime, generate_prime


def test_is_probable_prime_small():
    rng = XorShift64Star(12345)

    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in primes:
        ok, _, _ = is_probable_prime(p, rounds=8, rng=rng)
        assert ok, f"Expected {p} to be prime"

    composites = [1, 4, 6, 8, 9, 15, 21, 25, 27, 33]
    for c in composites:
        ok, _, _ = is_probable_prime(c, rounds=8, rng=rng)
        assert not ok, f"Expected {c} to be composite"


def test_generate_prime_bit_length():
    """generate_prime must produce a number with exactly the requested bit length."""
    rng = XorShift64Star(7)
    for bits in (32, 48, 64):
        p, _, _ = generate_prime(bits, rounds=12, rng=rng)
        assert p.bit_length() == bits, f"Expected {bits}-bit prime, got bit_length={p.bit_length()}"


def test_generate_prime_is_prime():
    """The number returned by generate_prime must pass a high-confidence Miller-Rabin check."""
    rng = XorShift64Star(42)
    p, _, _ = generate_prime(64, rounds=24, rng=rng)
    ok, _, _ = is_probable_prime(p, rounds=40, rng=XorShift64Star(99))
    assert ok, f"Generated value {p} did not pass primality test"