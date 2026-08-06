"""End-to-end tests driving `main()` the way the CLI does.

Previously this module rebuilt 512 KiB of plaintext *and* keys before each test with
`tempfile.NamedTemporaryFile(delete=False)` plus manual `os.unlink`. Credentials are now built once
per session by the fixtures in conftest.py, and the sizes are small enough to run in CI.
"""

import gzip

import pytest

from lenticrypt.__main__ import main

from .conftest import make_plaintexts


@pytest.fixture
def plaintext_files(tmp_path):
    paths = []
    for index, plaintext in enumerate(make_plaintexts((4096, 4096))):
        path = tmp_path / f"plaintext{index}"
        path.write_bytes(plaintext)
        paths.append(path)
    return tuple(paths)


def test_entropy_test_accepts_sufficient_keys(key_files_2):
    """`-t` exits zero when the secrets cover every byte combination."""
    for key in key_files_2:
        assert main(["lenticrypt", "-q", "-t", str(key)]) == 0


def test_entropy_test_rejects_weak_keys(tmp_path, weak_keys):
    """`-t` must exit non-zero on insufficient entropy. Nothing covered the failure path before."""
    path = tmp_path / "weak"
    path.write_bytes(weak_keys[0])
    assert main(["lenticrypt", "-q", "-t", str(path)]) == 1


def test_encrypt_decrypt_roundtrip(tmp_path, key_files_2, plaintext_files):
    ciphertext = tmp_path / "out.enc"
    argv = ["lenticrypt", "-q", "-o", str(ciphertext)]
    for key, plaintext in zip(key_files_2, plaintext_files, strict=True):
        argv += ["-e", str(key), str(plaintext)]
    assert main(argv) == 0
    assert ciphertext.stat().st_size > 0

    for key, plaintext in zip(key_files_2, plaintext_files, strict=True):
        decrypted = tmp_path / f"decrypted-{key.name}"
        assert (
            main(["lenticrypt", "-q", "-o", str(decrypted), "-d", str(key), str(ciphertext)]) == 0
        )
        assert decrypted.read_bytes() == plaintext.read_bytes()


def test_ciphertext_is_gzipped(tmp_path, key_files_2, plaintext_files):
    """Output is gzip-wrapped; `mtime=1` is set so a seeded run could be byte-reproducible."""
    ciphertext = tmp_path / "out.enc"
    argv = ["lenticrypt", "-q", "-o", str(ciphertext)]
    for key, plaintext in zip(key_files_2, plaintext_files, strict=True):
        argv += ["-e", str(key), str(plaintext)]
    assert main(argv) == 0
    with gzip.open(ciphertext) as decompressed:
        assert len(decompressed.read()) > 0


def test_insufficient_entropy_refuses_without_force(tmp_path, weak_keys, plaintext_files):
    """Encryption must refuse rather than emit a ciphertext that cannot round-trip."""
    argv = ["lenticrypt", "-q", "-o", str(tmp_path / "out.enc")]
    for index, key in enumerate(weak_keys):
        path = tmp_path / f"weak{index}"
        path.write_bytes(key)
        argv += ["-e", str(path), str(plaintext_files[index])]
    assert main(argv) == 1
