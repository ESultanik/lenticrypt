# Changelog

## 0.4.0 (unreleased)

The first release since 2019. It fixes two defects that could lose or expose data, so anything
encrypted with 0.3.x is worth revisiting.

### Fixed: ciphertexts could be silently wrong

**`--length-checksum` corrupted plaintexts.** In randomized testing, 34 of 120 round-trips returned
the right number of bytes with the wrong contents — and because the length header truncates the
output, the damage was invisible. It also affected equal-length plaintexts whenever an odd number of
single-nibble fallbacks left a nibble pending.

The cause: a nibble-gram reader could report "no data" both at end of stream and when it merely held
fewer nibbles than requested. The encrypter treated both as "pad", writing padding over live
plaintext and emitting a block without consuming anything, which shifted everything after it.

**If you have ciphertexts written with `--length-checksum`, verify they decrypt to what you
expect.** `--dictionary` (the default) and `--same-length` were not affected.

### Fixed: ciphertexts leaked their own filename

The gzip envelope recorded the output path in cleartext, because gzip derives the header FNAME field
from the file object it is given:

```
$ lenticrypt -o my-secret-plans.enc -e key1 p1 -e key2 p2
$ dd if=my-secret-plans.enc bs=1 skip=10 count=19
my-secret-plans.enc
```

For a tool whose purpose is plausible deniability, that is recoverable metadata in the first
30 bytes. New ciphertexts carry no filename and no timestamp.

### Fixed: other correctness defects

- **The default encryption mode hung forever** when the keys lacked entropy for some byte — exactly
  the case `-f/--force-encrypt` documents itself as handling.
- **`-v/--version` printed nothing at all**, and on Python 3.14 the same bug broke the test suite:
  `main()` closed stdout, discarding output still buffered above it.
- **`-5/--best` was silently identical to `-4`**, so 16-nibble-grams were unreachable.
- **`-t` reported every byte combination as missing** on failure, and printed them as control
  characters.
- **`--seed` did not actually produce reproducible output.** Dictionary indices depended on set
  iteration order, which varies with `PYTHONHASHSEED`.
- **An empty plaintext decrypted to one byte**, and a ciphertext declaring more bytes than it
  delivered returned a truncated plaintext silently. Both are now correct or refused.
- **`IOWrapper` indexed the file path instead of the file**, because `str` is itself a `Sequence`.
  `IOWrapper('-')` also closed `sys.stdin`.
- Malformed ciphertexts raised `struct.error`, `TypeError`, or `EOFError`. They now raise
  `MalformedCiphertextError`, and the CLI reports it as a message rather than a traceback.
- With color disabled, every log level printed bare, so redirecting stderr discarded the fact that
  a message was an ERROR.
- `ProgressBar` divided by zero for short keys, and drew against the first phase's scale forever.

### Changed

- **Certificate offsets are chosen with a CSPRNG** rather than Mersenne Twister, whose state is
  recoverable from enough output. Those offsets are the ciphertext. `--seed` still gives a
  reproducible generator, and now warns that reproducible means predictable.
- **Unknown ciphertext format versions are refused** instead of decoded as an older version, which
  produced garbage.
- **Nibble-gram lengths are chosen adaptively** from key size and secret count; `-1`..`-5` cap that
  choice rather than making it. Lengths that cannot be hit are no longer indexed:

  ```
  2 x 512 KiB keys   2.85s / 1109 MB  ->  0.24s / 62 MB
  2 x   2 MiB keys  12.40s / 4334 MB  ->  0.95s / 145 MB
  ```

  Ciphertext sizes are unchanged; the dropped lengths were never used.
- **Encryption and decryption stream**, so memory no longer scales with file size.
- Non-gzipped ciphertexts now decrypt, and `-d` accepts `-` for standard input.

### Removed and renamed

- `lenticrypt.lenticrypt` is now `lenticrypt.core`. The package re-exports the public names, so
  `from lenticrypt import ...` is unaffected; `from lenticrypt.lenticrypt import ...` is not.
- The package previously leaked `array`, `itertools`, `random`, `struct` and every imported `typing`
  name into its namespace via a bare star import. It now exports a deliberate `__all__`.
- `Encrypter`'s hooks changed shape: `process_nibble` and `process_nibbles` are replaced by
  `pad_nibble_gram`, `can_encode` and `encode_block`; `get_max_length` by `total_nibbles`;
  `get_tuple` and `are_valid_nibbles` are gone. Subclasses outside this package will need updating —
  deliberately breaking rather than silently changing behavior.
- `decrypt`'s `cert=` and `file_length=` parameters are no longer positional; they existed for an
  internal recursion that no longer happens.
- `AutoUnzippingStream` and `GzipIOWrapper` are replaced by `auto_unzip`.
- The version number no longer encodes the ciphertext format version as its minor component.
  `ENCRYPTION_VERSION` is a separate constant, still 3.

### Project

- Python 3.10 through 3.14, tested on Linux and Windows. The package previously could not be
  imported on Windows at all.
- Packaging moved from `setup.py` to `pyproject.toml` with hatchling; `py.typed` is shipped and the
  package is fully annotated.
- The test suite went from 7 non-deterministic tests to 256, including fixtures that pin the
  on-disk format so old ciphertexts keep decrypting.

## 0.3.1 (2019-02-15)

Python 3 port and color logging.
