import subprocess
import sys
import unittest

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


if __name__ == '__main__':
    unittest.main()
