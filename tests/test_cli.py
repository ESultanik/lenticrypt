import gzip
import subprocess
import sys
import unittest

import pytest

from lenticrypt.__main__ import main


class TestStdoutLifetime(unittest.TestCase):
    """Regression tests for `main()` closing the stdout it does not own.

    The `finally` block used to close `args.outfile` whenever it was not `sys.stdout`. The default
    outfile is `sys.stdout.buffer`, so the guard never matched and stdout was always closed. Two
    user-visible consequences, both covered here.
    """

    def test_version_is_actually_printed(self):
        """`--version` printed nothing at all: closing `sys.stdout.buffer` discarded the banner
        still sitting in the enclosing TextIOWrapper."""
        result = subprocess.run(
            [sys.executable, "-m", "lenticrypt", "--version"],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("Lenticrypt", result.stdout)
        self.assertIn("Cryptosystem Version", result.stdout)

    def test_stdout_survives_main(self):
        """Anything running after `main()` -- another test, an in-process caller -- hit
        `ValueError: I/O operation on closed file`."""
        self.assertEqual(main(["lenticrypt", "-q", "--version"]), 0)
        self.assertFalse(sys.stdout.buffer.closed)
        print("stdout is still usable")


if __name__ == "__main__":
    unittest.main()


class TestModeAndLevelSelection(unittest.TestCase):
    """The mode and level options were three and five overlapping `store_true` flags."""

    def test_mode_defaults_to_dictionary(self):
        from lenticrypt.__main__ import build_parser

        self.assertEqual(build_parser().parse_args(["-v"]).mode, "dictionary")

    def test_each_mode_is_reachable(self):
        from lenticrypt.__main__ import ENCRYPTERS, build_parser

        for flag, mode in (
            ("--same-length", "same-length"),
            ("--length-checksum", "length-checksum"),
            ("--dictionary", "dictionary"),
        ):
            args = build_parser().parse_args([flag, "-v"])
            self.assertEqual(args.mode, mode)
            self.assertIn(args.mode, ENCRYPTERS)

    def test_modes_are_mutually_exclusive(self):
        from lenticrypt.__main__ import build_parser

        with self.assertRaises(SystemExit):
            build_parser().parse_args(["--same-length", "--dictionary", "-v"])


def test_non_gzipped_ciphertext_decrypts(tmp_path, key_files_2):
    """`gzip.GzipFile(path)` raised an uncaught BadGzipFile traceback for anything not gzipped.

    The library writes plain ciphertexts; only the CLI wraps them in gzip. `auto_unzip` accepts
    either.
    """
    import io

    from lenticrypt import DictionaryEncrypter, find_common_nibble_grams

    keys = [path.read_bytes() for path in key_files_2]
    plaintexts = (bytes(range(32)), bytes(range(32, 64)))
    alphabet = find_common_nibble_grams(keys)
    plain = tmp_path / "plain.enc"
    plain.write_bytes(bytes(DictionaryEncrypter(alphabet, [io.BytesIO(p) for p in plaintexts])))

    out = tmp_path / "decrypted"
    assert main(["lenticrypt", "-q", "-o", str(out), "-d", str(key_files_2[0]), str(plain)]) == 0
    assert out.read_bytes() == plaintexts[0]


def test_gzipped_ciphertext_still_decrypts(tmp_path, key_files_2):
    """The normal path must keep working now that auto-detection is in place."""
    import io

    from lenticrypt import DictionaryEncrypter, find_common_nibble_grams

    keys = [path.read_bytes() for path in key_files_2]
    plaintexts = (bytes(range(32)), bytes(range(32, 64)))
    alphabet = find_common_nibble_grams(keys)
    zipped = tmp_path / "zipped.enc"
    zipped.write_bytes(
        gzip.compress(bytes(DictionaryEncrypter(alphabet, [io.BytesIO(p) for p in plaintexts])))
    )

    out = tmp_path / "decrypted"
    assert main(["lenticrypt", "-q", "-o", str(out), "-d", str(key_files_2[1]), str(zipped)]) == 0
    assert out.read_bytes() == plaintexts[1]


def test_missing_ciphertext_reports_cleanly(tmp_path, key_files_2):
    """A missing file should be an error message, not a traceback."""
    with pytest.raises((FileNotFoundError, SystemExit)):
        main(["lenticrypt", "-q", "-d", str(key_files_2[0]), str(tmp_path / "nope.enc")])


@pytest.mark.parametrize("level", ["-1", "-2", "-3", "-4", "-5"])
def test_every_compression_level_round_trips(tmp_path, key_files_2, level):
    """`-5` was unreachable, so the deepest index was never exercised end to end."""
    plaintexts = []
    for index, content in enumerate((bytes(range(48)), bytes(range(48, 96)))):
        path = tmp_path / f"plaintext{index}"
        path.write_bytes(content)
        plaintexts.append(path)
    ciphertext = tmp_path / f"out{level}.enc"
    argv = ["lenticrypt", "-q", level, "-o", str(ciphertext)]
    for key, plaintext in zip(key_files_2, plaintexts, strict=True):
        argv += ["-e", str(key), str(plaintext)]
    assert main(argv) == 0

    for key, plaintext in zip(key_files_2, plaintexts, strict=True):
        out = tmp_path / f"decrypted-{key.name}-{level}"
        assert main(["lenticrypt", "-q", "-o", str(out), "-d", str(key), str(ciphertext)]) == 0
        assert out.read_bytes() == plaintext.read_bytes()
