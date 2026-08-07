"""Ciphertext format compatibility.

The fixtures in `tests/data/` were produced by the released code, before any of the correctness
work. They must keep decrypting byte-for-byte forever: fixing the encrypters changes which
ciphertexts we *produce*, but must never change which ciphertexts we can *read*.

Deliberately decrypt-only. A golden *encrypt* comparison is not yet possible, because `--seed` does
not produce reproducible output: `DictionaryEncrypter.build_dictionary` iterates a set difference
over tuples of `bytes`, whose order varies with `PYTHONHASHSEED`, so dictionary indices differ run
to run. Once that is fixed, an encrypt-determinism assertion belongs here too.
"""

import io
from pathlib import Path

import pytest

from lenticrypt import decrypt

DATA = Path(__file__).parent / "data"

# One golden per version of the on-disk format, produced by Encrypter (v1, --same-length),
# LengthChecksumEncrypter (v2, --length-checksum) and DictionaryEncrypter (v3, the default).
GOLDEN_CIPHERTEXTS = ["v1_same_length", "v2_length_checksum", "v3_dictionary"]


@pytest.fixture(scope="module")
def golden_keys() -> tuple[bytes, ...]:
    return tuple((DATA / f"key{i}.bin").read_bytes() for i in range(2))


@pytest.fixture(scope="module")
def golden_plaintexts() -> tuple[bytes, ...]:
    return tuple((DATA / f"plaintext{i}.bin").read_bytes() for i in range(2))


@pytest.mark.parametrize("name", GOLDEN_CIPHERTEXTS)
def test_golden_ciphertext_still_decrypts(
    name: str, golden_keys: tuple[bytes, ...], golden_plaintexts: tuple[bytes, ...]
) -> None:
    ciphertext = (DATA / f"{name}.ct").read_bytes()
    for key, expected in zip(golden_keys, golden_plaintexts, strict=True):
        decrypted = bytes(decrypt(io.BytesIO(ciphertext), io.BytesIO(key)))
        assert decrypted == expected, f"{name} no longer decrypts to the original plaintext"


@pytest.mark.parametrize("name", GOLDEN_CIPHERTEXTS)
def test_golden_ciphertext_is_key_dependent(
    name: str, golden_keys: tuple[bytes, ...], golden_plaintexts: tuple[bytes, ...]
) -> None:
    """The whole point of the cryptosystem: one ciphertext, a different plaintext per key."""
    ciphertext = (DATA / f"{name}.ct").read_bytes()
    first = bytes(decrypt(io.BytesIO(ciphertext), io.BytesIO(golden_keys[0])))
    second = bytes(decrypt(io.BytesIO(ciphertext), io.BytesIO(golden_keys[1])))
    assert first != second
    assert (first, second) == golden_plaintexts
