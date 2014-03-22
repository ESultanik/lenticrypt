lenticrypt
==========

A simple cryptosystem that provides provable [plausibly deniable encryption](http://en.wikipedia.org/wiki/Deniable_encryption).  Lenticrypt can generate a single ciphertext file such that different plaintexts are generated depending on which key is used for decryption.

## Usage

```shell
$ python lenticrypt.py -e key1 plaintext1 -e key2 plaintext2 -o output.enc

$ python lenticrypt.py -d key1 output.enc | diff - plaintext1 -s
Files - and plaintext1 are identical

$ python lenticrypt.py -d key2 output.enc | diff - plaintext2 -s
Files - and plaintext2 are identical
```

Additional instructions are availble by running with the `-h` option.

## Author

Evan A. Sultanik, Ph.D.<br />
http://www.sultanik.com/<br />
http://www.digitaloperatives.com/
