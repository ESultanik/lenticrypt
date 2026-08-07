"""The nibble-gram index: expansion, packing, adaptive length selection, and chunked I/O."""

import array
import io
import random

import pytest

from lenticrypt import (
    DictionaryEncrypter,
    decrypt,
    decrypt_chunks,
    find_common_nibble_grams,
    nibbles_of,
    pack_grams,
    read_nibble_grams,
    read_nibbles,
    select_nibble_gram_lengths,
    unpack_gram_length,
)
from lenticrypt.rng import seeded_rng

from .conftest import make_keys, make_plaintexts


class TestNibbleExpansion:
    def test_matches_the_reference_implementation(self):
        """`bytes.translate` twice must equal the per-byte loop it replaced."""
        rng = random.Random(0)
        for size in (0, 1, 2, 17, 4096):
            data = rng.randbytes(size)
            reference = bytearray()
            for byte in data:
                reference.append((byte & 0b11110000) >> 4)
                reference.append(byte & 0b00001111)
            assert nibbles_of(data) == bytes(reference)

    def test_every_element_is_a_nibble(self):
        assert all(0 <= n <= 15 for n in nibbles_of(bytes(range(256))))

    def test_read_nibbles_agrees(self):
        data = bytes(range(64))
        assert bytes(read_nibbles(data)) == nibbles_of(data)


class TestNibbleGrams:
    @pytest.mark.parametrize("length", [1, 2, 4, 8, 16])
    def test_windows_are_one_nibble_apart(self, length):
        data = bytes(range(32))
        nibbles = nibbles_of(data)
        grams = list(read_nibble_grams(data, length))
        assert len(grams) == len(nibbles) - length + 1
        assert grams[0] == nibbles[:length]
        assert grams[1] == nibbles[1 : length + 1]

    def test_rejects_non_power_of_two(self):
        with pytest.raises(ValueError, match="power of two"):
            list(read_nibble_grams(b"abc", 3))


class TestPacking:
    @pytest.mark.parametrize("num_secrets", [1, 2, 3, 4])
    @pytest.mark.parametrize("length", [1, 2, 4])
    def test_pack_then_split_round_trips(self, num_secrets, length):
        """A packed key must be splittable back into each certificate's gram, since the dictionary
        header needs the gram length and the index is keyed on the packed form."""
        rng = random.Random(1)
        grams = tuple(bytes(rng.randrange(16) for _ in range(length)) for _ in range(num_secrets))
        key = pack_grams(grams)
        assert len(key) == length * num_secrets
        assert unpack_gram_length(key, num_secrets) == length
        assert tuple(key[i::num_secrets] for i in range(num_secrets)) == grams

    def test_packing_matches_the_index_layout(self):
        """`pack_grams` must produce exactly the key the interleaved index builder stores."""
        rng = random.Random(2)
        certs = tuple(rng.randbytes(256) for _ in range(2))
        index = find_common_nibble_grams(certs, nibble_gram_lengths=(2,))
        expanded = [nibbles_of(c) for c in certs]
        for offset in (0, 1, 5, 100):
            grams = tuple(bytes(n[offset : offset + 2]) for n in expanded)
            key = pack_grams(grams)
            assert key in index[2]
            assert offset in index[2][key]


class TestAdaptiveLengthSelection:
    @pytest.mark.parametrize(
        ("num_secrets", "kib", "expected"),
        [
            # Two secrets: length 2 needs 65,536 combinations, which a 256 KiB key covers.
            (2, 256, (1, 2)),
            (2, 32, (1, 2)),
            (2, 2048, (1, 2)),
            # Three secrets: length 2 needs 16.7M combinations, out of reach at any sane key size.
            (3, 32, (1,)),
            (3, 512, (1,)),
            (4, 512, (1,)),
            # One secret: length 4 needs only 65,536, so it is genuinely reachable.
            (1, 64, (1, 2, 4)),
        ],
    )
    def test_selection(self, num_secrets, kib, expected):
        assert select_nibble_gram_lengths(kib * 1024, num_secrets) == expected

    def test_length_one_is_always_included(self):
        """Without it no byte can be encoded at all, however short the certificates."""
        for num_secrets in (1, 2, 3, 6):
            assert select_nibble_gram_lengths(1, num_secrets)[0] == 1

    def test_respects_an_explicit_cap(self):
        assert select_nibble_gram_lengths(64 * 1024, 1, max_length=2) == (1, 2)


class TestIndex:
    def test_offsets_are_stored_compactly(self):
        """`array('L')` is native width -- 8 bytes here, 4 on Windows -- so it was both
        platform-dependent and twice the size needed."""
        certs = (bytes(range(256)), bytes(range(255, -1, -1)))
        index = find_common_nibble_grams(certs, nibble_gram_lengths=(1,))
        offsets = next(iter(index[1].values()))
        assert isinstance(offsets, array.array)
        assert offsets.itemsize == 4

    def test_recorded_offsets_are_correct(self):
        rng = random.Random(3)
        certs = tuple(rng.randbytes(512) for _ in range(2))
        index = find_common_nibble_grams(certs, nibble_gram_lengths=(1, 2))
        expanded = [nibbles_of(c) for c in certs]
        for length, entries in index.items():
            for key, offsets in list(entries.items())[:50]:
                for offset in offsets:
                    rebuilt = pack_grams(
                        tuple(bytes(n[offset : offset + length]) for n in expanded)
                    )
                    assert rebuilt == key

    def test_defaults_to_adaptive_lengths(self):
        rng = random.Random(4)
        certs = tuple(rng.randbytes(4096) for _ in range(2))
        assert tuple(find_common_nibble_grams(certs)) == select_nibble_gram_lengths(4096, 2)

    def test_stop_when_sufficient_threshold(self):
        """The threshold was `(16*L)**N`, correct only for L=1 by coincidence; it is `16**(L*N)`."""
        # One RNG for both: a fresh `Random(5)` per certificate would make them identical, and
        # identical certificates only ever share grams with themselves.
        rng = random.Random(5)
        certs = tuple(rng.randbytes(1 << 15) for _ in range(2))
        index = find_common_nibble_grams(certs, nibble_gram_lengths=(1,), stop_when_sufficient=True)
        assert len(index[1]) == 16**2


@pytest.fixture(scope="module")
def credentials():
    """Keys, their index, and two plaintexts -- built once for the chunking tests."""
    keys = make_keys(2)
    return keys, find_common_nibble_grams(keys), make_plaintexts((4096, 4096))


class TestChunkedOutput:
    """Chunked encrypt and decrypt must produce exactly what the whole-buffer paths produce."""

    @pytest.mark.parametrize("chunk_size", [1, 7, 64, 4096, 1 << 20])
    def test_encrypt_chunks_reassemble_to_the_same_ciphertext(self, chunk_size, credentials):
        _keys, alphabet, plaintexts = credentials
        # An explicit seeded generator: the encrypters no longer read module-level `random`, so
        # `random.seed()` cannot make two runs agree.
        whole = bytes(
            DictionaryEncrypter(alphabet, [io.BytesIO(p) for p in plaintexts], rng=seeded_rng(11))
        )
        chunked = b"".join(
            DictionaryEncrypter(
                alphabet, [io.BytesIO(p) for p in plaintexts], rng=seeded_rng(11)
            ).chunks(chunk_size)
        )
        assert chunked == whole

    def test_chunks_respect_the_requested_size(self, credentials):
        _keys, alphabet, plaintexts = credentials
        sizes = [
            len(c)
            for c in DictionaryEncrypter(
                alphabet, [io.BytesIO(p) for p in plaintexts], rng=seeded_rng(11)
            ).chunks(1024)
        ]
        # Every chunk but the last reaches the threshold; blocks are small, so none overshoot much.
        assert all(1024 <= size < 1024 + 16 for size in sizes[:-1])
        assert sizes[-1] <= 1024 + 16

    @pytest.mark.parametrize("chunk_size", [1, 7, 64, 4096, 1 << 20])
    def test_decrypt_chunks_reassemble_to_the_same_plaintext(self, chunk_size, credentials):
        keys, alphabet, plaintexts = credentials
        ciphertext = bytes(
            DictionaryEncrypter(alphabet, [io.BytesIO(p) for p in plaintexts], rng=seeded_rng(11))
        )
        whole = bytes(decrypt(io.BytesIO(ciphertext), io.BytesIO(keys[0])))
        chunked = b"".join(
            decrypt_chunks(io.BytesIO(ciphertext), io.BytesIO(keys[0]), chunk_size=chunk_size)
        )
        assert chunked == whole == plaintexts[0]
