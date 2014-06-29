lenticrypt
==========

A simple cryptosystem that provides provable [plausibly deniable encryption](http://en.wikipedia.org/wiki/Deniable_encryption).  Lenticrypt can generate a single ciphertext file such that different plaintexts are generated depending on which key is used for decryption.

## Details

Unlike alternative plausibly deniable cryptosystems like the recently discontinued [TrueCrypt](http://en.wikipedia.org/wiki/TrueCrypt)—whose ciphertext size grows in proportion to the number of plaintexts (*i.e.*, hidden volumes) it encrypts—Lenticrypt's ciphertext size is proportional to the *largest* plaintext it encrypts.  This is because Lenticrypt shares bytes in the cyphertext between each of the plaintexts it encrypts; they are not stored in separate regions of the ciphertext. Therefore, there is no straightforward way to estimate the number of plaintexts that are "hidden" inside a single ciphertext.

In fact, Lenticrypt has the theoretical property that, under reasonable assumptions, there is always a near 100% probability that there exists an key in the public domain that will decrypt a given ciphertext to *any* desired plaintext, even if that key is not known.

More technical details on the cryptosystem as well as additional use-cases are described in [Issue 0x04](http://www.sultanik.com/pocorgtfo/pocorgtfo04.pdf) of [The International Journal of PoC||GTFO](http://www.sultanik.com/pocorgtfo/).

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
