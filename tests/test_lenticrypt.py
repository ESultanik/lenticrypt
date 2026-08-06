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
ENCRYPTER_IDS = [cls.__name__ for cls in ENCRYPTERS]

# Several sizes, because how many single-nibble fallbacks occur -- and so whether a stray nibble is
# left pending at the end -- varies with length. A single size let the padding corruption through.
SIZES = (64, 128, 256, 512)


@pytest.mark.parametrize("encrypter_class", ENCRYPTERS, ids=ENCRYPTER_IDS)
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


@pytest.mark.parametrize("encrypter_class", ENCRYPTERS, ids=ENCRYPTER_IDS)
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
