"""Random number generation for encryption.

Every ciphertext block records a certificate offset chosen at random from the offsets where that
nibble-gram occurs. Those choices *are* the ciphertext, so the generator behind them matters: with
Mersenne Twister, observing enough output reveals the generator state and hence every subsequent
choice.

`random.SystemRandom` is the obvious fix but is far too slow to be the default, because a choice is
made roughly once per plaintext byte. Measured over 200,000 `choice()` calls on a 4096-element
array:

    Random (Mersenne Twister)   0.134 us
    SystemRandom                1.911 us     14x slower
    BufferedSystemRandom        0.502 us     3.8x faster than SystemRandom

`BufferedSystemRandom` draws `os.urandom` in blocks instead of per call, which recovers most of the
gap while keeping the CSPRNG.
"""

import os
import random

# How much entropy to draw from the OS at a time. Large enough that the syscall cost disappears,
# small enough not to hold meaningful amounts of unused key material around.
URANDOM_BLOCK_BYTES = 1 << 16


class BufferedSystemRandom(random.SystemRandom):
    """A `SystemRandom` that reads `os.urandom` in blocks rather than on every call.

    Inherits `SystemRandom`'s refusal to be seeded or pickled, so it cannot be mistaken for a
    reproducible generator.
    """

    def __init__(self, block_bytes: int = URANDOM_BLOCK_BYTES) -> None:
        super().__init__()
        self._block_bytes = block_bytes
        self._buffer = b""
        self._position = 0

    def _take(self, count: int) -> bytes:
        """Returns `count` fresh bytes, refilling from the OS when the buffer runs out."""
        if self._position + count > len(self._buffer):
            self._buffer = os.urandom(max(self._block_bytes, count))
            self._position = 0
        chunk = self._buffer[self._position : self._position + count]
        self._position += count
        return chunk

    def getrandbits(self, k: int) -> int:
        """Returns `k` random bits. `choice`, `randrange` and `randint` all route through this."""
        if k < 0:
            message = "number of bits must be non-negative"
            raise ValueError(message)
        if k == 0:
            return 0
        num_bytes = (k + 7) // 8
        return int.from_bytes(self._take(num_bytes), "big") >> (num_bytes * 8 - k)

    def randbytes(self, n: int) -> bytes:
        return self._take(n)

    def random(self) -> float:
        return self.getrandbits(53) * 2**-53


def default_rng() -> random.Random:
    """The generator used when no seed is requested."""
    return BufferedSystemRandom()


def seeded_rng(seed: int) -> random.Random:
    """A reproducible generator, for `--seed`. Explicitly *not* suitable for real use."""
    return random.Random(seed)  # noqa: S311 -- reproducibility is the whole point here
