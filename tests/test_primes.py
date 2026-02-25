from cryptolab.crypto.prng import XorShift64Star
from cryptolab.crypto.primes import is_probable_prime

def test_is_probable_prime_small():
    rng = XorShift64Star(12345) # seed for repeatability

    primes = [3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in primes:
        ok, _, _ = is_probable_prime(p, rounds=8, rng=rng) # 8 rounds is enough for small primes
        assert ok
    

    composites = [1, 4, 6, 8, 9, 15, 21, 25, 27, 33]
    for c in composites:
        ok, _, _ = is_probable_prime(c, rounds=8, rng=rng) # 8 rounds is enough for small primes
        assert not ok