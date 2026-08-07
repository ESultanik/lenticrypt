Lenticrypt
==========

A proof-of-concept cryptosystem that provides provable [plausibly deniable encryption](http://en.wikipedia.org/wiki/Deniable_encryption).  Lenticrypt can generate a single ciphertext file such that _different_ plaintexts are generated depending on which key is used for decryption.

## Details

Unlike alternative plausibly deniable cryptosystems like discontinued [TrueCrypt](http://en.wikipedia.org/wiki/TrueCrypt)—whose ciphertext size grows in proportion to the number of plaintexts (_i.e._, hidden volumes) it encrypts—Lenticrypt's ciphertext size is proportional to the _largest_ plaintext it encrypts.  This is because Lenticrypt shares bytes in the cyphertext between each of the plaintexts it encrypts; they are not stored in separate regions of the ciphertext. Therefore, there is no straightforward way to estimate the number of plaintexts that are “hidden” inside a single ciphertext.

In fact, Lenticrypt has the theoretical property that, under reasonable assumptions, there is always a near 100% probability that there exists a key in the public domain that will decrypt a given ciphertext to _any_ desired plaintext, even if that key is not known.  Therefore, even if an incriminating plaintext is revealed, the author of the ciphertext can plausibly deny having created it because there is a non-zero probability that the plaintext was legitimately decrypted by random chance. Creating the legal precedent for this theoretical property is left as an exercise for the reader.

Lenticrypt _can_ provide secrecy, but it does not _guarantee_ it. _**Do not**_ rely on Lenticrypt alone if you care about the secrecy of your plaintexts!

More technical details on the cryptosystem as well as additional use-cases are described in [Issue 0x04](https://www.sultanik.com/pocorgtfo/#0x04) of [The International Journal of PoC||GTFO](https://www.sultanik.com/pocorgtfo/).

## Installation

```shell
$ uv tool install lenticrypt      # or: pip install lenticrypt
```

Requires Python 3.10 or newer, and has no runtime dependencies.

## Usage

```shell
$ lenticrypt -e key1 plaintext1 -e key2 plaintext2 -o output.enc

$ lenticrypt -d key1 output.enc | diff - plaintext1 -s
Files - and plaintext1 are identical

$ lenticrypt -d key2 output.enc | diff - plaintext2 -s
Files - and plaintext2 are identical
```

Both gzipped and plain ciphertexts are accepted on decryption, and `-` reads from standard input.
Additional instructions are available by running with the `-h` option.

### Choosing keys

The keys must jointly contain every byte combination the plaintexts use, or those bytes cannot be
encoded. `-t` checks a set of keys before you rely on them, and exits non-zero if they fall short:

```shell
$ lenticrypt -t key1 key2
This set of secrets looks good!
```

Large, high-entropy files make good keys. `-f` forces encryption with insufficient keys, but the
ciphertext will not decrypt back to the original plaintexts.

### Reproducible output

`--seed` makes the ciphertext reproducible, which also makes it predictable. It exists for testing;
do not use it for anything you need kept secret. Without it, certificate offsets are drawn from the
operating system's CSPRNG.

## Performance

Encryption indexes the keys first, and that index dominates both time and memory. The nibble-gram
lengths worth indexing are chosen from the key size and the number of secrets, because a length-L
match needs every key to agree at the same offset — so the longer lengths are unreachable unless
the keys are enormous. The `-1` through `-5` options cap that choice rather than making it.

For two 512 KiB keys the index takes about 0.25s and 62 MB. Encryption itself then runs at roughly
6 seconds per MiB of plaintext, which is the dominant cost for anything sizeable.

Ciphertexts are larger than the plaintext, by a factor that improves with size as the dictionary
header is amortized — measured with two secrets, at 5.5x for 512 B, 4.4x at 4 KiB, 3.5x at 64 KiB,
and 2.7x at 512 KiB. Size tracks the *largest* plaintext, not the number of them.

Both encryption and decryption stream, so memory does not scale with file size.

## Development

```shell
$ uv sync
$ uv run pytest -q
$ uv run ruff check && uv run ruff format --check
$ uv run ty check
```

If your environment sets `exclude-newer` in a uv config file, regenerate the lockfile with
`uv --no-config lock`; a plain `uv lock` bakes that policy into `uv.lock`.

## File format

Ciphertexts are gzip-wrapped. Three format versions exist and all three still decrypt:

| version | option | notes |
|---|---|---|
| 1 | `--same-length` | No length header, so plaintexts of unequal length are truncated or zero-padded |
| 2 | `--length-checksum` | Encrypted length header, so unequal lengths round-trip |
| 3 | `--dictionary` | Adds an index dictionary. The default. Shrinks ciphertexts above roughly 8 KiB of plaintext; below that its header costs more than it saves |

## Author

Evan A. Sultanik, Ph.D.<br />
https://www.sultanik.com/
