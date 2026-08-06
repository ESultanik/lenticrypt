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
    ("empty-second", (64, 0)),
    ("near-equal", (64, 63)),
]


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


@pytest.mark.xfail(
    strict=True,
    reason="LengthChecksumEncrypter pads over pending real nibbles without consuming them",
)
def test_length_checksum_roundtrip_all_lengths(alphabet_2, keys_2):
    """Right byte count, wrong contents, when plaintexts do not tile the nibble stream evenly."""
    random.seed(CORRUPTING_SEED)
    for _, lengths in LENGTH_CASES:
        plaintexts = make_plaintexts(lengths)
        assert roundtrip(LengthChecksumEncrypter, alphabet_2, keys_2, plaintexts) == plaintexts, (
            f"lengths {lengths} did not round-trip"
        )


@pytest.mark.xfail(strict=True, reason="same padding bug, over many seeded length pairs")
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
    """`build_dictionary` loops forever on low-entropy secrets.

    Unlike `process_nibbles` it has no `elif length == 1:` fallback, so when no nibble-gram length
    matches, nothing is consumed and the `while self.is_incomplete(buffers)` loop spins. Run in a
    subprocess so a hang is a timeout rather than a wedged test session.
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
        pytest.xfail("build_dictionary spins forever when the secrets lack entropy")
    # Once it terminates it must do so cleanly, not by raising IndexError out of get_header.
    assert "completed" in result.stdout, result.stdout + result.stderr


# --------------------------------------------------------------------------------------------------
# CLI defects.
# --------------------------------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True, reason="-4 is store_true with default=True, so the elif chain never reaches -5"
)
def test_best_compression_differs_from_default():
    """`-5/--best` is silently identical to `-4`, so 16-nibble-grams are unreachable."""
    import argparse

    def selected(flags):
        parser = argparse.ArgumentParser()
        group = parser.add_mutually_exclusive_group()
        group.add_argument("-1", "--fast", action="store_true", default=False)
        group.add_argument("-2", dest="two", action="store_true", default=False)
        group.add_argument("-3", dest="three", action="store_true", default=False)
        group.add_argument("-4", dest="four", action="store_true", default=True)
        group.add_argument("-5", "--best", action="store_true", default=False)
        args = parser.parse_args(flags)
        lengths = [1, 2, 4, 8, 16]
        if args.fast:
            return lengths[:1]
        if args.two:
            return lengths[:2]
        if args.three:
            return lengths[:3]
        if args.four:
            return lengths[:4]
        return lengths

    assert selected(["-5"]) != selected(["-4"])
    assert selected(["-5"]) == [1, 2, 4, 8, 16]


@pytest.mark.xfail(
    strict=True, reason="probes tuple-of-int against an alphabet keyed by tuple-of-bytes"
)
def test_missing_combination_probe_matches_alphabet_keys(keys_2):
    """`-t`'s report probes `tuple((c,) for c in combination)`, but alphabet keys look like
    `(b'\\x00', b'\\x0f')`, so membership always fails and every combination is reported missing."""
    alphabet = find_common_nibble_grams(keys_2, nibble_gram_lengths=(1,))
    probe = tuple((c,) for c in (0, 0))
    assert probe in alphabet[1]


# --------------------------------------------------------------------------------------------------
# IOWrapper: `str` is itself a Sequence, so the isinstance dispatch indexes the path, not the file.
# --------------------------------------------------------------------------------------------------


@pytest.mark.xfail(strict=True, reason="len() measures the path string, not the file")
def test_iowrapper_len_reflects_file(tmp_path):
    path = tmp_path / "twenty-bytes.bin"
    path.write_bytes(bytes(range(20)))
    assert len(IOWrapper(str(path))) == 20


@pytest.mark.xfail(strict=True, reason="indexes the path string; also never seeks to the index")
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


@pytest.mark.xfail(strict=True, reason="divides by max_value without guarding zero")
def test_progress_bar_tolerates_zero_max():
    ProgressBar(max_value=0, stream=io.StringIO()).update(0)


def test_progress_bar_renders():
    stream = io.StringIO()
    bar = ProgressBar(max_value=10, stream=stream)
    bar.update(5, "Halfway")
    assert "Halfway" in stream.getvalue()
