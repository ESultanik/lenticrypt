#!/usr/bin/env python3

import itertools
import random
import unittest
from io import BytesIO

import lenticrypt


def random_string(length):
    s = bytearray()
    for i in range(length):
        s.append(random.randint(0, 255))
    return s


def make_valid_keys(n):
    """makes keys that have enough entropy to encrypt n different plaintexts"""
    remaining = list(itertools.product(*itertools.tee(range(255), n)))
    return tuple(bytes(r[k] for r in remaining) for k in range(n))


class TestLenticrypt(unittest.TestCase):
    def setUp(self):
        self.plaintexts = tuple(random_string(1024) for _ in range(3))
        while True:
            self.keys = tuple(random_string(2**15) for _ in range(len(self.plaintexts)))
            #self.keys = make_valid_keys(len(self.plaintexts))
            self.substitution_alphabet = lenticrypt.find_common_nibble_grams(self.keys)
            if len(self.substitution_alphabet[1]) >= 16**len(self.plaintexts):
                break

    def plaintext_io(self):
        return [BytesIO(s) for s in self.plaintexts]

    def test_basic_encryption(self):
        ciphertexts = itertools.tee(lenticrypt.Encrypter(self.substitution_alphabet, self.plaintext_io()), len(self.plaintexts))
        first_length = None
        for key, plaintext, ciphertext in zip(self.keys, self.plaintexts, ciphertexts):
            decrypted = bytes(lenticrypt.decrypt(ciphertext, BytesIO(key)))
            if first_length is None:
                first_length = len(plaintext)
            else:
                if first_length > len(plaintext):
                    decrypted = decrypted[:len(plaintext)]
                elif first_length < len(plaintext):
                    plaintext = plaintext[:first_length]
            self.assertEqual(decrypted, plaintext)

    def test_checksum_encryption(self):
        ciphertexts = itertools.tee(lenticrypt.LengthChecksumEncrypter(self.substitution_alphabet, self.plaintext_io()), len(self.plaintexts))
        for key, plaintext, ciphertext in zip(self.keys, self.plaintexts, ciphertexts):
            decrypted = bytes(lenticrypt.decrypt(ciphertext, BytesIO(key)))
            self.assertEqual(decrypted, plaintext)

    def test_dictionary_encryption(self):
        ciphertexts = itertools.tee(lenticrypt.DictionaryEncrypter(self.substitution_alphabet, self.plaintext_io()), len(self.plaintexts))
        for key, plaintext, ciphertext in zip(self.keys, self.plaintexts, ciphertexts):
            decrypted = bytes(lenticrypt.decrypt(ciphertext, BytesIO(key)))
            self.assertEqual(decrypted, plaintext)

    def test_encoding(self):
        for i in range(5000):
            n = random.randint(1, lenticrypt.MAX_ENCODE_VALUE-1)
            self.assertEqual(n, lenticrypt.decode(lenticrypt.encode(n)))
        # also make sure to test the extremal cases!
        self.assertEqual(0, lenticrypt.decode(lenticrypt.encode(0)))
        self.assertEqual(lenticrypt.MAX_ENCODE_VALUE, lenticrypt.decode(lenticrypt.encode(lenticrypt.MAX_ENCODE_VALUE)))


if __name__ == '__main__':
    unittest.main()
