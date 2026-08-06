"""Shared, deterministic test credentials.

Every helper here is seeded. The suite used to rely on unseeded `random`, and
`tests/test_lenticrypt.py` regenerated 3 x 32 KiB keys in an unbounded `while True:` loop until it
happened to draw enough entropy -- so runtime and outcome both varied run to run.

Keys are built *constructively* instead: the first `16**n` bytes of every key are laid out so that
all `16**n` one-nibble-gram combinations are covered by construction, which is what the cryptosystem
needs in order to encode any byte. A seeded random tail follows, to give the multi-nibble-gram
lengths (2, 4, 8, ...) enough coverage to actually be exercised.
"""

import itertools
import random

import pytest

from lenticrypt import find_common_nibble_grams

# Enough random tail for ~40% coverage of the 2-nibble-gram keyspace at n=2, so encryption really
# does emit 2-nibble-gram blocks rather than falling back to single nibbles everywhere.
DEFAULT_KEY_TAIL_BYTES = 1 << 14


def make_keys(
    num_secrets: int, tail_bytes: int = DEFAULT_KEY_TAIL_BYTES, seed: int = 0
) -> tuple[bytes, ...]:
    """Builds `num_secrets` keys that jointly cover every one-nibble-gram combination.

    Args:
        num_secrets: How many keys to build.
        tail_bytes: Seeded random bytes appended to each key, for multi-nibble-gram coverage.
        seed: Seed for the random tail.

    Returns:
        One `bytes` object per secret, all of the same length.
    """
    keys = [bytearray() for _ in range(num_secrets)]
    grams = sorted(itertools.product(range(16), repeat=num_secrets))
    # Pack consecutive grams into bytes: gram i lands at nibble offset 2*i in every key at once, so
    # after this loop every combination is present at some shared offset.
    for gram, following in itertools.zip_longest(grams, grams[1:], fillvalue=(0,) * num_secrets):
        for key, high, low in zip(keys, gram, following, strict=True):
            key.append((high << 4) | low)
    rng = random.Random(seed)
    for key in keys:
        key.extend(rng.randbytes(tail_bytes))
    return tuple(bytes(key) for key in keys)


def make_plaintexts(lengths: tuple[int, ...], seed: int = 1) -> tuple[bytes, ...]:
    """Builds one seeded random plaintext per entry in `lengths`."""
    rng = random.Random(seed)
    return tuple(rng.randbytes(length) for length in lengths)


def make_weak_keys(num_secrets: int = 2, num_bytes: int = 512) -> tuple[bytes, ...]:
    """Builds keys with deliberately insufficient entropy: only the all-zero gram is covered."""
    return tuple(bytes(num_bytes) for _ in range(num_secrets))


@pytest.fixture(autouse=True)
def _seed_global_random() -> None:
    """Seeds the module-level `random` before every test.

    The encrypters draw padding and certificate offsets from module-level `random`, so results
    depend on global RNG state -- which means test outcomes depended on which tests ran earlier.
    Individual tests override this seed where they need a specific one.
    """
    random.seed(0x1EE7)


@pytest.fixture(scope="session")
def keys_2() -> tuple[bytes, ...]:
    return make_keys(2)


@pytest.fixture(scope="session")
def keys_3() -> tuple[bytes, ...]:
    return make_keys(3)


@pytest.fixture(scope="session")
def alphabet_2(keys_2: tuple[bytes, ...]):
    """The substitution alphabet for `keys_2`. Session-scoped: building it is the expensive part."""
    return find_common_nibble_grams(keys_2)


@pytest.fixture(scope="session")
def alphabet_3(keys_3: tuple[bytes, ...]):
    return find_common_nibble_grams(keys_3)


@pytest.fixture(scope="session")
def weak_keys() -> tuple[bytes, ...]:
    return make_weak_keys()


@pytest.fixture(scope="session")
def key_files_2(keys_2: tuple[bytes, ...], tmp_path_factory: pytest.TempPathFactory):
    """`keys_2` written to disk, for tests that drive the CLI."""
    directory = tmp_path_factory.mktemp("keys")
    paths = []
    for index, key in enumerate(keys_2):
        path = directory / f"key{index}"
        path.write_bytes(key)
        paths.append(path)
    return tuple(paths)
