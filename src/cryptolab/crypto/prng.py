from __future__ import annotations 

"""
Simple manual PRNG (pseudorandom number generator) for demonstration purposes.
Reason for inclusion: 
    - We need reproducible generations of random numbers for testing and demonstration, and a simple PRNG allows us to control the randomness while still showing the concept of randomness in cryptographic algorithms.
    - We can't use secrets/random for cryptography
    - For repeatable and transparent testing
We use a classic xorshift* style generator, which is simple and fast, but not cryptographically secure but helps understand the concept of a PRNG and how it can be used in cryptographic contexts (like key generation, nonce generation, etc.) without relying on external libraries.
"""

import os
import time

class XorShift64Star:
    def __init__(self, seed: int | None = None) -> None:
        if seed is None: 
            seed = int(time.time_ns()) ^ (os.getpid() << 16) # combine time and process id for some variability)
            
        self.state = seed & ((1 << 64) - 1) # ensure state is 64 bits
        if self.state == 0:
            self.state = 0x9E3779B97F4A7C15 # default non-zero seed if 0 is given which avoids the all zero state which would produce only zeros
    
    def next_u64(self) -> int:
        x = self.state
        x ^= (x >> 12) & ((1 << 64) - 1) # right shift and xor
        x ^= (x << 25) & ((1 << 64) - 1) # left shift and xor
        x ^= (x >> 27) & ((1 << 64) - 1) # right shift and xor
        self.state = x
        return (x * 2685821657736338717) & ((1 << 64) - 1) # multiply by a constant and ensure 64 bits and the long number: 2685821657736338717 is a specific constant used in xorshift* generators to improve the quality of the output.

    def randbits(self, k: int) -> int:
        if k <= 0:
            return 0
        out = 0
        produced = 0
        while produced < k:
            chunk = self.next_u64()
            take = min(64, k - produced) # take at most 64 bits from the chunk
            out |= (chunk & ((1 << take) - 1)) << produced # take the lower 'take' bits and shift them into position
            produced += take
        return out
    
    def randint(self, a: int, b: int) -> int:
        """Return int in [a, b]"""
        if a > b:
            raise ValueError("a must be <= b")
        span = b - a + 1
        if span == 1:
            return a
        
        #rejection sampling which is used to reduce modulo bias when the range is not a power of 2
        limit = (1 << 64) - ((1 << 64) % span) # largest multiple of span less than 2^64
        while True:
            r = self.next_u64()
            if r < limit: # only accept values less than limit to avoid bias
                return a + (r % span)
            
