#!/usr/bin/env python2

import unittest
import lenticrypt
import StringIO
import random

def random_string(length):
    s = ""
    for i in range(length):
        s += chr(random.randint(0, 255))
    return s

class TestLenticrypt(unittest.TestCase):
    def setUp(self):
        self.plaintexts = [random_string(random.randint(1,1024)) for i in range(3)]
        while True:
            self.keys = [random_string(random.randint(2**14,2**15)) for i in range(3)]
            self.substitution_alphabet = lenticrypt.find_common_nibble_grams(map(lambda k : map(ord, k), self.keys))
            if len(self.substitution_alphabet[1]) >= 16**3:
                break

    def test_basic_encryption(self):
        ciphertext = "".join(lenticrypt.Encrypter(self.substitution_alphabet, map(lambda s : StringIO.StringIO(s), self.plaintexts)))
        first_length = None
        for key, plaintext in zip(self.keys, self.plaintexts):
            decrypted = "".join(lenticrypt.decrypt(StringIO.StringIO(ciphertext), StringIO.StringIO(key)))
            if first_length is None:
                first_length = len(plaintext)
            else:
                if first_length > len(plaintext):
                    decrypted = decrypted[:len(plaintext)]
                elif first_length < len(plaintext):
                    plaintext = plaintext[:first_length]
            self.assertEqual(decrypted, plaintext)

    def test_checksum_encryption(self):
        ciphertext = "".join(lenticrypt.LengthChecksumEncrypter(self.substitution_alphabet, map(lambda s : StringIO.StringIO(s), self.plaintexts)))
        for key, plaintext in zip(self.keys, self.plaintexts):
            decrypted = "".join(lenticrypt.decrypt(StringIO.StringIO(ciphertext), StringIO.StringIO(key)))
            self.assertEqual(decrypted, plaintext)

    def test_dictionary_encryption(self):
        ciphertext = "".join(lenticrypt.DictionaryEncrypter(self.substitution_alphabet, map(lambda s : StringIO.StringIO(s), self.plaintexts)))
        for key, plaintext in zip(self.keys, self.plaintexts):
            decrypted = "".join(lenticrypt.decrypt(StringIO.StringIO(ciphertext), StringIO.StringIO(key)))
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
