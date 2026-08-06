"""The gzip envelope must not leak anything about the plaintexts or the invocation.

Lenticrypt's whole claim is that a ciphertext reveals nothing -- not even how many plaintexts it
holds. A gzip header that records the output filename undermines that before any cryptanalysis
starts.
"""

import gzip
import subprocess
import sys

import pytest

from lenticrypt.__main__ import main

GZIP_FLG_FNAME = 0x08


@pytest.fixture
def encrypt(tmp_path, key_files_2):
    """Returns a callable that encrypts two small plaintexts to a named output file."""

    def run(output_name: str, extra_args: tuple[str, ...] = ()) -> bytes:
        plaintexts = []
        for index, content in enumerate((bytes(range(32)), bytes(range(32, 64)))):
            path = tmp_path / f"plaintext{index}"
            path.write_bytes(content)
            plaintexts.append(path)
        output = tmp_path / output_name
        argv = ["lenticrypt", "-q", *extra_args, "-o", str(output)]
        for key, plaintext in zip(key_files_2, plaintexts, strict=True):
            argv += ["-e", str(key), str(plaintext)]
        assert main(argv) == 0
        return output.read_bytes()

    return run


def test_ciphertext_does_not_embed_the_output_filename(encrypt):
    """`-o my-secret-plans.enc` used to store "my-secret-plans.enc" in the gzip header."""
    ciphertext = encrypt("my-secret-plans.enc")
    assert not ciphertext[3] & GZIP_FLG_FNAME, "gzip FNAME flag is set; a filename is embedded"
    assert b"my-secret-plans" not in ciphertext


def test_ciphertext_is_independent_of_the_output_filename(encrypt):
    """Output depended on the output path, which alone made `--seed` non-reproducible."""
    short = encrypt("a.enc", ("-s", "42"))
    long = encrypt("a-considerably-longer-name.enc", ("-s", "42"))
    assert short == long


def test_ciphertext_carries_no_timestamp(encrypt):
    """mtime is pinned so two runs of the same input are byte-identical."""
    ciphertext = encrypt("out.enc", ("-s", "42"))
    assert ciphertext[4:8] == b"\x01\x00\x00\x00"


def test_seeded_output_is_reproducible_across_hash_seeds(tmp_path, key_files_2):
    """A fixed `--seed` must give identical bytes regardless of PYTHONHASHSEED."""
    plaintexts = []
    for index, content in enumerate((bytes(range(32)), bytes(range(32, 64)))):
        path = tmp_path / f"plaintext{index}"
        path.write_bytes(content)
        plaintexts.append(path)

    digests = set()
    for hash_seed in ("1", "99999"):
        output = tmp_path / f"out-{hash_seed}.enc"
        argv = [sys.executable, "-m", "lenticrypt", "-q", "-s", "42", "-o", str(output)]
        for key, plaintext in zip(key_files_2, plaintexts, strict=True):
            argv += ["-e", str(key), str(plaintext)]
        subprocess.run(  # noqa: S603 -- our own interpreter, arguments built here
            argv, check=True, env={"PYTHONHASHSEED": hash_seed, "PATH": ""}
        )
        digests.add(gzip.decompress(output.read_bytes()))
    assert len(digests) == 1, "ciphertext still varies with PYTHONHASHSEED at a fixed seed"
