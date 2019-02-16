Lenticrypt
==========

A proof-of-concept cryptosystem that provides provable [plausibly deniable encryption](http://en.wikipedia.org/wiki/Deniable_encryption).  Lenticrypt can generate a single ciphertext file such that _different_ plaintexts are generated depending on which key is used for decryption.

## Details

Unlike alternative plausibly deniable cryptosystems like discontinued [TrueCrypt](http://en.wikipedia.org/wiki/TrueCrypt)—whose ciphertext size grows in proportion to the number of plaintexts (_i.e._, hidden volumes) it encrypts—Lenticrypt's ciphertext size is proportional to the _largest_ plaintext it encrypts.  This is because Lenticrypt shares bytes in the cyphertext between each of the plaintexts it encrypts; they are not stored in separate regions of the ciphertext. Therefore, there is no straightforward way to estimate the number of plaintexts that are “hidden” inside a single ciphertext.

In fact, Lenticrypt has the theoretical property that, under reasonable assumptions, there is always a near 100% probability that there exists a key in the public domain that will decrypt a given ciphertext to _any_ desired plaintext, even if that key is not known.  Therefore, even if an incriminating plaintext is revealed, the author of the ciphertext can plausibly deny having created it because there is a non-zero probability that the plaintext was legitimately decrypted by random chance. Creating the legal precedent for this theoretical property is left as an exercise for the reader.

Lenticrypt _can_ provide secrecy, but it does not _guarantee_ it. _**Do not**_ rely on Lenticrypt alone if you care about the secrecy of your plaintexts! 

More technical details on the cryptosystem as well as additional use-cases are described in [Issue 0x04](https://www.sultanik.com/pocorgtfo/pocorgtfo04.pdf) of [The International Journal of PoC||GTFO](https://www.sultanik.com/pocorgtfo/).

## Installation

```shell
$ pip3 install lenticrypt
```

## Usage

```shell
$ lenticrypt -e key1 plaintext1 -e key2 plaintext2 -o output.enc

$ lenticrypt -d key1 output.enc | diff - plaintext1 -s
Files - and plaintext1 are identical

$ lenticrypt -d key2 output.enc | diff - plaintext2 -s
Files - and plaintext2 are identical
```

Additional instructions are available by running with the `-h` option.

## Author

Evan A. Sultanik, Ph.D.<br />
https://www.sultanik.com/
