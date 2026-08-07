"""Regression tests for defects found reviewing the 2019 code.

Tests covering a defect that is still present are marked `xfail(strict=True)`. Strict matters: when
the fix lands the test XPASSes, which strict mode reports as a failure, forcing the fixing commit to
drop the marker. That keeps CI honest -- green now, and green after the fix -- without ever
pretending the bug is not there.
"""

import io
import random
import subprocess
import sys

import pytest

from lenticrypt import (
    DictionaryEncrypter,
    LengthChecksumEncrypter,
    decode,
    decrypt,
    find_common_nibble_grams,
)
from lenticrypt.iowrapper import IOWrapper
from lenticrypt.progress import ProgressBar

from .conftest import make_plaintexts

# --------------------------------------------------------------------------------------------------
# Encrypter round-trips across plaintext length combinations.
#
# `LengthChecksumEncrypter` corrupts plaintexts: 34 of 120 randomized round-trips returned the
# right byte count with the wrong contents. `peek_nibbles(L)` returns None both at true EOF *and*
# when real data remains but is shorter than L; `process_nibble` pads over the live data,
# `are_valid_nibbles` uses max() so the mixed tuple passes validation, and `get_nibbles(L)` then
# consumes nothing. The real nibbles are re-emitted later, shifting the plaintext.
# --------------------------------------------------------------------------------------------------

LENGTH_CASES = [
    ("equal", (64, 64)),
    ("first-longer", (64, 37)),
    ("first-shorter", (37, 64)),
    ("odd-both", (31, 17)),
    ("one-byte", (1, 64)),
    ("near-equal", (64, 63)),
]

# Kept out of LENGTH_CASES because it fails for an unrelated reason -- see
# test_empty_plaintext_roundtrip, which is a decrypt-side defect rather than an encrypter one.
EMPTY_CASE = (64, 0)


def roundtrip(encrypter_class, alphabet, keys, plaintexts):
    ciphertext = bytes(encrypter_class(alphabet, [io.BytesIO(p) for p in plaintexts]))
    return tuple(
        bytes(decrypt(io.BytesIO(ciphertext), io.BytesIO(key))) for key in keys[: len(plaintexts)]
    )


# Whether a given case corrupts depends on the module-level RNG, because the padding nibbles are
# drawn from it and corruption only occurs when a padded gram happens to be in the substitution
# alphabet. Seeding makes that fully deterministic (verified stable across repeated runs), so these
# tests fix the seed rather than marking individual length pairs.
CORRUPTING_SEED = 2024


def test_length_checksum_roundtrip_all_lengths(alphabet_2, keys_2):
    """Right byte count, wrong contents, when plaintexts do not tile the nibble stream evenly."""
    random.seed(CORRUPTING_SEED)
    for _, lengths in LENGTH_CASES:
        plaintexts = make_plaintexts(lengths)
        assert roundtrip(LengthChecksumEncrypter, alphabet_2, keys_2, plaintexts) == plaintexts, (
            f"lengths {lengths} did not round-trip"
        )


@pytest.mark.parametrize(
    "encrypter_class",
    [
        pytest.param(
            LengthChecksumEncrypter,
            id="LengthChecksumEncrypter",
            marks=pytest.mark.xfail(
                strict=True,
                reason="decrypt emits a byte before testing file_length, so 0 bytes yields 1",
            ),
        ),
        pytest.param(DictionaryEncrypter, id="DictionaryEncrypter"),
    ],
)
def test_empty_plaintext_roundtrip(encrypter_class, alphabet_2, keys_2):
    """An empty plaintext must decrypt to nothing.

    `decrypt` only compares `num_bytes` against `file_length` *after* yielding, so a declared length
    of zero still produces one byte. A decrypt-side defect, not an encrypter one.
    """
    random.seed(CORRUPTING_SEED)
    plaintexts = make_plaintexts(EMPTY_CASE)
    assert roundtrip(encrypter_class, alphabet_2, keys_2, plaintexts) == plaintexts


def test_length_checksum_seeded_sweep(alphabet_2, keys_2):
    random.seed(CORRUPTING_SEED)
    rng = random.Random(CORRUPTING_SEED)
    for _ in range(40):
        lengths = (rng.randint(1, 96), rng.randint(1, 96))
        plaintexts = make_plaintexts(lengths, seed=rng.randint(0, 1 << 30))
        assert roundtrip(LengthChecksumEncrypter, alphabet_2, keys_2, plaintexts) == plaintexts


@pytest.mark.parametrize("lengths", [c[1] for c in LENGTH_CASES], ids=[c[0] for c in LENGTH_CASES])
def test_dictionary_roundtrip(lengths, alphabet_2, keys_2):
    """The default mode escapes the padding bug: the random padding drawn during the dictionary pass
    differs from the one drawn while encrypting, so padded grams never match the dictionary."""
    random.seed(CORRUPTING_SEED)
    plaintexts = make_plaintexts(lengths)
    assert roundtrip(DictionaryEncrypter, alphabet_2, keys_2, plaintexts) == plaintexts


def test_three_secret_roundtrip(alphabet_3, keys_3):
    """Nothing covered n=3 deterministically before."""
    plaintexts = make_plaintexts((48, 48, 48))
    assert roundtrip(DictionaryEncrypter, alphabet_3, keys_3, plaintexts) == plaintexts


# --------------------------------------------------------------------------------------------------
# Insufficient entropy: the `-f/--force-encrypt` path.
# --------------------------------------------------------------------------------------------------


def test_dictionary_encrypter_terminates_on_weak_keys():
    """`build_dictionary` used to loop forever on low-entropy secrets.

    It had its own walk with no `length == 1` fallback, so when no nibble-gram length matched,
    nothing was consumed and `while self.is_incomplete(buffers)` spun -- the `-f/--force-encrypt`
    case. Run in a subprocess so a regression is a timeout rather than a wedged test session.
    """
    program = """
import io, sys
from lenticrypt import find_common_nibble_grams, DictionaryEncrypter
weak = (bytes(512), bytes(512))
alphabet = find_common_nibble_grams(weak)
plaintexts = [io.BytesIO(bytes([1, 2, 3, 4])), io.BytesIO(bytes([5, 6, 7, 8]))]
try:
    bytes(DictionaryEncrypter(alphabet, plaintexts))
except Exception as e:
    print(f"raised {type(e).__name__}")
else:
    print("completed")
"""
    try:
        result = subprocess.run(  # noqa: S603 -- our own interpreter, fixed program
            [sys.executable, "-c", program],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("build_dictionary hung: the length-1 fallback has regressed")
    # It must also terminate *cleanly*. Force-adding every 16**n single-nibble gram, including ones
    # the alphabet cannot encode, made get_header raise IndexError off a defaultdict's empty array.
    assert "completed" in result.stdout, result.stdout + result.stderr


def test_dictionary_header_survives_unencodable_grams(weak_keys):
    """Building a dictionary from secrets that cannot encode every byte must still emit a header."""
    alphabet = find_common_nibble_grams(weak_keys)
    plaintexts = [io.BytesIO(bytes([1, 2, 3, 4])), io.BytesIO(bytes([5, 6, 7, 8]))]
    encrypter = DictionaryEncrypter(alphabet, plaintexts)
    assert bytes(encrypter.get_header())
    # Only grams the alphabet can actually encode may enter the dictionary.
    for grams in encrypter.dictionary_items:
        assert grams in alphabet[len(grams[0])]


def test_seeded_encryption_is_reproducible(alphabet_2):
    """`--seed` promised reproducible output but did not deliver it.

    build_dictionary iterated `missing_grams - dictionary_hits.keys()`, a set difference over tuples
    of `bytes`, whose iteration order varies with PYTHONHASHSEED. Dictionary indices therefore
    differed between runs even at a fixed seed. Sorting the entries fixes it; this test pins it
    within a process, and test_cli covers it across processes with differing hash seeds.
    """
    plaintexts = make_plaintexts((128, 128))

    def encrypt_once():
        random.seed(4242)
        return bytes(DictionaryEncrypter(alphabet_2, [io.BytesIO(p) for p in plaintexts]))

    assert encrypt_once() == encrypt_once()


# --------------------------------------------------------------------------------------------------
# CLI defects.
# --------------------------------------------------------------------------------------------------


def test_best_compression_differs_from_default():
    """`-5/--best` was silently identical to `-4`.

    The five levels were separate `store_true` flags with `-4` defaulting to True, so the
    dispatching `elif` chain reached `-4` before it could consider `-5`, and 16-nibble-grams were
    unreachable. Exercises the real parser rather than a replica of the old logic.
    """
    from lenticrypt.__main__ import NIBBLE_GRAM_LENGTHS, build_parser

    def lengths(flags):
        return NIBBLE_GRAM_LENGTHS[: build_parser().parse_args([*flags, "-v"]).level]

    assert lengths(["-5"]) != lengths(["-4"])
    assert lengths(["-5"]) == (1, 2, 4, 8, 16)
    assert lengths(["-4"]) == (1, 2, 4, 8)
    assert lengths([]) == (1, 2, 4, 8), "the default is still -4"
    for level, expected in enumerate([(1,), (1, 2), (1, 2, 4), (1, 2, 4, 8)], start=1):
        assert lengths([f"-{level}"]) == expected


def test_missing_combinations_uses_the_alphabet_key_shape(keys_2, weak_keys):
    """`-t`'s report probed `tuple((c,) for c in combination)` -- a tuple of int-tuples -- against
    an alphabet keyed by tuples of `bytes`, so membership never matched and every combination was
    reported missing."""
    from lenticrypt.__main__ import missing_combinations

    assert missing_combinations(find_common_nibble_grams(keys_2, nibble_gram_lengths=(1,)), 2) == []
    missing = missing_combinations(find_common_nibble_grams(weak_keys, nibble_gram_lengths=(1,)), 2)
    assert len(missing) == 255, "weak keys cover only the all-zero gram"
    assert all(isinstance(part, bytes) for gram in missing for part in gram)


# --------------------------------------------------------------------------------------------------
# IOWrapper: `str` is itself a Sequence, so the isinstance dispatch indexes the path, not the file.
# --------------------------------------------------------------------------------------------------


def test_iowrapper_len_reflects_file(tmp_path):
    path = tmp_path / "twenty-bytes.bin"
    path.write_bytes(bytes(range(20)))
    assert len(IOWrapper(str(path))) == 20


def test_iowrapper_getitem_reflects_file(tmp_path):
    path = tmp_path / "twenty-bytes.bin"
    path.write_bytes(bytes(range(20)))
    assert IOWrapper(str(path))[5] == 5


def test_iowrapper_accepts_bytes():
    """The bytes path works today; pinned so the rewrite cannot regress it."""
    assert len(IOWrapper(bytes(range(20)))) == 20
    assert IOWrapper(bytes(range(20)))[5] == 5


# --------------------------------------------------------------------------------------------------
# Malformed ciphertext should produce a clean error, not a raw stdlib traceback.
# --------------------------------------------------------------------------------------------------


def test_decode_returns_none_at_eof():
    assert decode(b"") is None


@pytest.mark.xfail(strict=True, reason="struct.error escapes; should be a LenticryptError")
def test_truncated_length_header_raises_cleanly(keys_2):
    truncated = bytes([0b10000011])
    with pytest.raises(ValueError) as excinfo:
        bytes(decrypt(io.BytesIO(truncated), io.BytesIO(keys_2[0])))
    assert "struct" not in type(excinfo.value).__module__


@pytest.mark.xfail(
    strict=True, reason="`range(decode(stream))` with decode() -> None raises TypeError"
)
def test_truncated_dictionary_raises_cleanly(keys_2):
    # A v3 length header, then a plausible length, then nothing where the dictionary should be.
    header = bytes([0b10000000 | 3])
    with pytest.raises(ValueError):
        bytes(decrypt(io.BytesIO(header + bytes(40)), io.BytesIO(keys_2[0])))


def test_empty_ciphertext_yields_nothing(keys_2):
    assert bytes(decrypt(io.BytesIO(b""), io.BytesIO(keys_2[0]))) == b""


# --------------------------------------------------------------------------------------------------
# Progress bar.
# --------------------------------------------------------------------------------------------------


def test_progress_bar_renders():
    stream = io.StringIO()
    bar = ProgressBar(max_value=10, stream=stream)
    bar.update(5, "Halfway")
    assert "Halfway" in stream.getvalue()
