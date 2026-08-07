"""Random number generation.

Certificate offsets chosen at random *are* the ciphertext, so the generator behind them is part of
the security story rather than an implementation detail.
"""

import io
import random
from collections import Counter

import pytest

from lenticrypt import DictionaryEncrypter, find_common_nibble_grams
from lenticrypt.rng import BufferedSystemRandom, default_rng, seeded_rng

from .conftest import make_keys, make_plaintexts


class TestBufferedSystemRandom:
    def test_is_a_system_random(self):
        assert isinstance(default_rng(), random.SystemRandom)

    def test_cannot_be_seeded_into_reproducibility(self):
        """Inheriting SystemRandom's no-op `seed` is the point: it cannot be mistaken for
        reproducible."""
        first, second = BufferedSystemRandom(), BufferedSystemRandom()
        first.seed(42)
        second.seed(42)
        assert [first.getrandbits(32) for _ in range(8)] != [
            second.getrandbits(32) for _ in range(8)
        ]

    def test_rejects_pickling(self):
        with pytest.raises(NotImplementedError):
            BufferedSystemRandom().getstate()

    @pytest.mark.parametrize("bits", [1, 7, 8, 31, 32, 53, 64, 256])
    def test_getrandbits_respects_its_width(self, bits):
        rng = BufferedSystemRandom()
        for _ in range(64):
            assert 0 <= rng.getrandbits(bits) < (1 << bits)

    def test_getrandbits_zero(self):
        assert BufferedSystemRandom().getrandbits(0) == 0

    def test_getrandbits_rejects_negative(self):
        with pytest.raises(ValueError, match="non-negative"):
            BufferedSystemRandom().getrandbits(-1)

    def test_random_is_in_range(self):
        rng = BufferedSystemRandom()
        for _ in range(256):
            assert 0.0 <= rng.random() < 1.0

    def test_randbytes_length(self):
        rng = BufferedSystemRandom()
        for size in (0, 1, 17, 1 << 17):
            assert len(rng.randbytes(size)) == size

    def test_refills_across_the_block_boundary(self):
        """A small block size forces many refills; output must stay well distributed."""
        rng = BufferedSystemRandom(block_bytes=8)
        counts = Counter(rng.getrandbits(8) for _ in range(20000))
        assert len(counts) > 200, "byte values should be spread across the range"
        assert max(counts.values()) < 400, "no value should dominate"

    def test_choice_covers_the_sequence(self):
        rng = BufferedSystemRandom()
        pool = list(range(32))
        assert {rng.choice(pool) for _ in range(2000)} == set(pool)


@pytest.fixture(scope="module")
def alphabet_and_plaintexts():
    keys = make_keys(2)
    return find_common_nibble_grams(keys), make_plaintexts((256, 256))


class TestEncrypterRandomness:
    def encrypt(self, alphabet, plaintexts, **kwargs):
        return bytes(DictionaryEncrypter(alphabet, [io.BytesIO(p) for p in plaintexts], **kwargs))

    def test_default_output_differs_between_runs(self, alphabet_and_plaintexts):
        """Without a seed, two encryptions of the same input must not coincide."""
        alphabet, plaintexts = alphabet_and_plaintexts
        assert self.encrypt(alphabet, plaintexts) != self.encrypt(alphabet, plaintexts)

    def test_seeded_output_is_reproducible(self, alphabet_and_plaintexts):
        alphabet, plaintexts = alphabet_and_plaintexts
        assert self.encrypt(alphabet, plaintexts, rng=seeded_rng(7)) == self.encrypt(
            alphabet, plaintexts, rng=seeded_rng(7)
        )

    def test_different_seeds_differ(self, alphabet_and_plaintexts):
        alphabet, plaintexts = alphabet_and_plaintexts
        assert self.encrypt(alphabet, plaintexts, rng=seeded_rng(7)) != self.encrypt(
            alphabet, plaintexts, rng=seeded_rng(8)
        )

    def test_module_level_seeding_no_longer_affects_output(self, alphabet_and_plaintexts):
        """The encrypters used to draw from module-level `random`, so anything else in the process
        touching it changed the ciphertext."""
        alphabet, plaintexts = alphabet_and_plaintexts
        random.seed(1234)
        first = self.encrypt(alphabet, plaintexts)
        random.seed(1234)
        assert self.encrypt(alphabet, plaintexts) != first

    def test_nested_length_header_encrypter_shares_the_generator(self, alphabet_and_plaintexts):
        """LengthChecksumEncrypter builds a nested Encrypter for the length header; if that one kept
        its own generator, a seeded run would still vary."""
        alphabet, plaintexts = alphabet_and_plaintexts
        first = self.encrypt(alphabet, plaintexts, rng=seeded_rng(99))
        second = self.encrypt(alphabet, plaintexts, rng=seeded_rng(99))
        assert first == second
        # The header is where the nested encrypter writes, so compare the leading bytes explicitly.
        assert first[:32] == second[:32]
