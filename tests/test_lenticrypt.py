"""Library-level tests for the three encrypters and the varint codec."""

import io
import itertools
import random

import pytest

from lenticrypt import (
    MAX_ENCODE_VALUE,
    DictionaryEncrypter,
    Encrypter,
    LengthChecksumEncrypter,
    decode,
    decrypt,
    encode,
)

from .conftest import make_plaintexts

ENCRYPTERS = [Encrypter, LengthChecksumEncrypter, DictionaryEncrypter]

# LengthChecksumEncrypter corrupts the tail even when the plaintexts are the *same* length:
# whenever an odd number of single-nibble fallbacks leaves one nibble pending, `peek_nibbles(2)`
# reports None, the padding policy overwrites that live nibble, and nothing is consumed.
# See test_regressions.py.
PADDING_BUG = pytest.mark.xfail(
    strict=True, reason="LengthChecksumEncrypter pads over a pending real nibble"
)
ENCRYPTERS_PARAMS = [
    pytest.param(
        cls,
        id=cls.__name__,
        marks=PADDING_BUG if cls is LengthChecksumEncrypter else (),
    )
    for cls in ENCRYPTERS
]


# Whether a given plaintext size trips the padding bug depends on how many single-nibble fallbacks
# happen to occur, so these tests sweep several sizes rather than pinning one. A single size would
# make the xfail below pass or fail by luck.
SIZES = (64, 128, 256, 512)


@pytest.mark.parametrize("encrypter_class", ENCRYPTERS_PARAMS)
def test_equal_length_roundtrip(encrypter_class, alphabet_2, keys_2):
    """Every mode must round-trip equal-length plaintexts.

    `Encrypter` (--same-length) has no length header, so equal lengths are the only case where
    all of its plaintexts decrypt exactly; the unequal cases live in test_regressions.py.
    """
    for size in SIZES:
        plaintexts = make_plaintexts((size, size))
        ciphertext = bytes(encrypter_class(alphabet_2, [io.BytesIO(p) for p in plaintexts]))
        for key, expected in zip(keys_2, plaintexts, strict=True):
            actual = bytes(decrypt(io.BytesIO(ciphertext), io.BytesIO(key)))
            assert actual == expected, f"{size}-byte plaintexts did not round-trip"


@pytest.mark.parametrize("encrypter_class", ENCRYPTERS_PARAMS)
def test_one_ciphertext_yields_different_plaintexts(encrypter_class, alphabet_2, keys_2):
    """The defining property: the same bytes decrypt differently under each key."""
    for size in SIZES:
        plaintexts = make_plaintexts((size, size))
        ciphertext = bytes(encrypter_class(alphabet_2, [io.BytesIO(p) for p in plaintexts]))
        decrypted = [bytes(decrypt(io.BytesIO(ciphertext), io.BytesIO(k))) for k in keys_2]
        assert decrypted[0] != decrypted[1]
        assert tuple(decrypted) == plaintexts


def test_decrypt_accepts_an_iterable_of_ints(alphabet_2, keys_2):
    """`decrypt` wraps its ciphertext in an IOWrapper, so a bare iterator of ints is valid input."""
    plaintexts = make_plaintexts((64, 64))
    streams = itertools.tee(
        Encrypter(alphabet_2, [io.BytesIO(p) for p in plaintexts]), len(plaintexts)
    )
    for stream, key, expected in zip(streams, keys_2, plaintexts, strict=True):
        assert bytes(decrypt(stream, io.BytesIO(key))) == expected


def test_dictionary_shrinks_the_ciphertext(alphabet_2):
    """The dictionary shrinks the ciphertext -- but only above roughly 8 KiB of plaintext.

    Below that its header (one entry per distinct nibble-gram pair) costs more than it saves, so the
    dictionary mode is a pessimization for small inputs even though it is the default. Measured
    crossover with these keys: 2 KiB plaintext -> 9401 B dictionary vs 8790 B length-checksum;
    8 KiB plaintext -> 34518 B vs 35341 B.
    """
    plaintexts = make_plaintexts((8192, 8192))

    def size(cls):
        return len(bytes(cls(alphabet_2, [io.BytesIO(p) for p in plaintexts])))

    assert size(DictionaryEncrypter) < size(LengthChecksumEncrypter)


class TestVarintCodec:
    def test_roundtrip_seeded(self):
        rng = random.Random(0xC0DE)
        for _ in range(1000):
            n = rng.randint(1, MAX_ENCODE_VALUE - 1)
            assert decode(encode(n)) == n

    @pytest.mark.parametrize("n", [0, 1, 127, 128, 16383, 16384, MAX_ENCODE_VALUE])
    def test_roundtrip_boundaries(self, n):
        """Values either side of each width transition, plus both extremes."""
        assert decode(encode(n)) == n

    def test_too_large_is_rejected(self):
        with pytest.raises(Exception, match="too big to encode"):
            encode(MAX_ENCODE_VALUE + 1)

    def test_width_grows_with_magnitude(self):
        assert len(encode(0)) == 1
        assert len(encode(MAX_ENCODE_VALUE)) == 7
