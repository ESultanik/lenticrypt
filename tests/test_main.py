import itertools
import os
import random
import tempfile
import unittest

from typing import BinaryIO, Sequence, Tuple

from lenticrypt.__main__ import main


def make_plaintexts(streams: Sequence[BinaryIO], num_bytes=2048) -> Tuple[Tuple[int, ...]]:
    necessary_nibble_grams = set()
    for _ in range(num_bytes):
        to_write = tuple(random.randint(0, 255) for _ in range(len(streams)))
        ng_msb = tuple((b & 0b11110000) >> 4 for b in to_write)
        ng_lsb = tuple(b & 0b00001111 for b in to_write)
        necessary_nibble_grams.add(ng_msb)
        necessary_nibble_grams.add(ng_lsb)
        for i, stream in enumerate(streams):
            stream.write(bytes([to_write[i]]))
    return tuple(necessary_nibble_grams)


def make_keys(streams: Sequence[BinaryIO], necessary_nibble_grams: Tuple[Tuple[int, ...]]):
    """makes keys that have enough entropy to encrypt n different plaintexts"""
    #remaining = itertools.tee(itertools.product(*itertools.tee(range(255), len(streams))), len(streams))
    def necessary_bytes(ng):
        for nibble1, nibble2 in itertools.zip_longest(ng, ng[1:]):
            if nibble2 is None:
                nibble2 = (0,) * len(nibble1)
            yield tuple((n1 << 4) | n2 for n1, n2 in zip(nibble1, nibble2))
    for nb in necessary_bytes(necessary_nibble_grams):
        for stream, b in zip(streams, nb):
            stream.write(bytes([b]))


def make_credentials(num_secrets, num_bytes=2048) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    plaintexts = tuple(tempfile.NamedTemporaryFile(delete=False) for _ in range(num_secrets))
    necessary_nibble_grams = make_plaintexts(plaintexts, num_bytes)
    for plaintext in plaintexts:
        plaintext.close()
    key_files = tuple(tempfile.NamedTemporaryFile(delete=False) for _ in range(num_secrets))
    make_keys(key_files, necessary_nibble_grams)
    for key in key_files:
        key.close()
    return tuple(k.name for k in key_files), tuple(p.name for p in plaintexts)


class TestMain(unittest.TestCase):
    def setUp(self):
        self.keys, self.plaintexts = make_credentials(2, num_bytes=1048576//2)

    def tearDown(self):
        for f in itertools.chain(self.keys, self.plaintexts):
            if os.path.exists(f):
                os.unlink(f)

    def test_entropy_test(self):
        args = ['lenticrypt', '-q']
        for k in self.keys:
            self.assertEqual(main(args + ['-t', k]), 0)

    def test_crypto(self):
        encrypted = tempfile.NamedTemporaryFile(delete=False)
        encrypted.close()
        encrypted = encrypted.name

        try:
            args = ['lenticrypt', '-q', '-f', '-o', encrypted]
            for k, p in zip(self.keys, self.plaintexts):
                args += ['-e', k, p]
            self.assertEqual(main(args), 0)

            for k, p in zip(self.keys, self.plaintexts):
                decrypted = tempfile.NamedTemporaryFile(delete=False)
                decrypted.close()
                decrypted = decrypted.name

                try:
                    args = ['lenticrypt', '-q', '-f', '-o', decrypted, '-d', k, encrypted]
                    self.assertEqual(main(args), 0)

                    with open(p, 'rb') as original:
                        with open(decrypted, 'rb') as d:
                            self.assertEqual(original.read(), d.read())
                finally:
                    if os.path.exists(decrypted):
                        os.unlink(decrypted)
        finally:
            if os.path.exists(encrypted):
                os.unlink(encrypted)


if __name__ == '__main__':
    unittest.main()
