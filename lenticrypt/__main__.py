import argparse
import contextlib
import gzip
import itertools
import logging
import random
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import BinaryIO, cast

from .core import (
    ENCRYPTION_VERSION,
    VERSION,
    DictionaryEncrypter,
    Encrypter,
    LengthChecksumEncrypter,
    decrypt_chunks,
    find_common_nibble_grams,
    select_nibble_gram_lengths,
)
from .exceptions import LenticryptError
from .iowrapper import auto_unzip
from .logger import DEFAULT_FORMAT as DEFAULT_LOG_FORMAT
from .logger import ColorFormatter
from .progress import ProgressBarCallback
from .rng import default_rng, seeded_rng

logger = logging.getLogger(name="lenticrypt")

COPYRIGHT = "Copyright (C) 2012--2019, Evan A. Sultanik, Ph.D.  \nhttps://www.sultanik.com/\n"

# Compression levels select a prefix of this list. Longer nibble-grams compress better but need
# proportionally more certificate material to be usable at all.
NIBBLE_GRAM_LENGTHS = (1, 2, 4, 8, 16)

LOG_LEVELS = ("QUIET", "CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG")

ENCRYPTERS = {
    "same-length": Encrypter,
    "length-checksum": LengthChecksumEncrypter,
    "dictionary": DictionaryEncrypter,
}

# Cap on how many missing byte combinations `-t` names individually. With four secrets there are
# 65,536 of them, and a wall of output helps nobody.
MAX_REPORTED_COMBINATIONS = 64


def _add_action_arguments(parser: argparse.ArgumentParser) -> None:
    """The mutually exclusive "what are we doing" group."""
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-e",
        "--encrypt",
        action="append",
        nargs=2,
        metavar=("secret", "plaintext"),
        help="encrypts the given plaintext file(s) into a single ciphertext using the given "
        "secret file(s). Additional secret/plaintext pairs can be specified by providing `-e` "
        "multiple times, for example `-e secret1 plaintext1 -e secret2 plaintext2`. With "
        "`--same-length`, any plaintext longer than the first is truncated and any shorter one "
        "is tail-padded with zeros.",
    )
    group.add_argument(
        "-d",
        "--decrypt",
        nargs=2,
        type=str,
        metavar=("secret", "ciphertext"),
        help="decrypts the ciphertext file using the given secret file. Gzipped and plain "
        "ciphertexts are both accepted. Use `-` to read the ciphertext from standard input.",
    )
    group.add_argument(
        "-t",
        "--test",
        nargs="+",
        metavar="secret",
        help="tests whether a given set of secrets has sufficient entropy to encrypt an equal "
        "number of plaintexts. The exit code is zero on success. On failure, the missing byte "
        "combinations are logged to stderr.",
    )
    group.add_argument(
        "-v", "--version", action="store_true", default=False, help="prints version information"
    )


def _add_mode_arguments(parser: argparse.ArgumentParser) -> None:
    """How the ciphertext is framed. One `store_const` rather than three overlapping booleans."""
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--same-length",
        dest="mode",
        action="store_const",
        const="same-length",
        help="omits the header that records the plaintext lengths. That header is what allows "
        "plaintexts of unequal length, so without it encryption is lossy unless they match. "
        "Slightly strengthens plausible deniability, at the cost of potentially large ciphertexts.",
    )
    group.add_argument(
        "--length-checksum",
        dest="mode",
        action="store_const",
        const="length-checksum",
        help="records an encrypted plaintext-length header, so plaintexts of differing lengths "
        "decrypt correctly, at a slight cost to plausible deniability. Can produce large "
        "ciphertexts.",
    )
    group.add_argument(
        "--dictionary",
        dest="mode",
        action="store_const",
        const="dictionary",
        help="uses the `--length-checksum` header plus an index dictionary, which can greatly "
        "reduce ciphertext size for plaintexts of more than a few kilobytes. This is the default.",
    )
    parser.set_defaults(mode="dictionary")


def _add_level_arguments(parser: argparse.ArgumentParser) -> None:
    """Compression level. `store_const` on one destination, so every level is reachable.

    These were five separate `store_true` flags with `-4` defaulting to True, so the dispatching
    `elif` chain reached `-4` before it could ever consider `-5`, making `--best` a silent no-op.
    """
    group = parser.add_mutually_exclusive_group()
    for level, flags in enumerate(
        [("-1", "--fast"), ("-2",), ("-3",), ("-4",), ("-5", "--best")], start=1
    ):
        group.add_argument(
            *flags,
            dest="level",
            action="store_const",
            const=level,
            help="These options set the compression level: -1 is fastest with least compression, "
            "-5 is slowest with the most. CPU and memory use grow sharply with the level, because "
            "each one indexes a longer nibble-gram. The default is -4."
            if level == 5
            else argparse.SUPPRESS,
        )
    parser.set_defaults(level=4)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="A toy cryptosystem with provable plausible deniability.  " + COPYRIGHT,
        prog="lenticrypt",
    )
    _add_action_arguments(parser)
    parser.add_argument(
        "-f",
        "--force-encrypt",
        action="store_true",
        default=False,
        help="force encryption even if the secrets have insufficient entropy to correctly encrypt "
        "the plaintexts",
    )
    parser.add_argument(
        "-o",
        "--outfile",
        nargs="?",
        default=None,
        help="the output file (defaults to stdout)",
    )
    _add_mode_arguments(parser)
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False,
        help="suppresses log messages; equivalent to `--log-level QUIET`",
    )
    parser.add_argument(
        "-l",
        "--log-level",
        type=str.upper,
        choices=LOG_LEVELS,
        default="INFO",
        help="set Lenticrypt's log level (default: INFO)",
    )
    _add_level_arguments(parser)
    parser.add_argument(
        "-s",
        "--seed",
        type=int,
        default=None,
        help="seeds the random number generator, making the ciphertext reproducible",
    )
    return parser


def configure_logging(args: argparse.Namespace) -> None:
    if args.quiet or args.log_level == "QUIET":
        logger.setLevel(logging.CRITICAL)
        use_color = False
    else:
        logger.setLevel(getattr(logging, args.log_level))
        use_color = sys.stderr.isatty()
    logger.propagate = False
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(ColorFormatter(DEFAULT_LOG_FORMAT, use_color=use_color))
        logger.addHandler(handler)


def _progress_callback(args: argparse.Namespace) -> ProgressBarCallback | None:
    """A progress bar only when there is a terminal to draw it on."""
    if args.quiet or not sys.stderr.isatty():
        return None
    return ProgressBarCallback()


def missing_combinations(substitution_alphabet: dict, num_secrets: int) -> list[bytes]:
    """The single-nibble combinations the secrets cannot encode.

    The probe used to build `tuple((c,) for c in combination)` -- a tuple of int-tuples -- and test
    it against an alphabet keyed by tuples of `bytes`. Membership could never succeed, so on failure
    every combination was reported missing.
    """
    single_grams = substitution_alphabet.get(1, {})
    return [
        key
        for key in (
            bytes(combination) for combination in itertools.product(range(16), repeat=num_secrets)
        )
        if key not in single_grams
    ]


def _format_missing(missing: Sequence[bytes]) -> str:
    """Renders missing combinations as hex nibbles.

    Previously rendered with `chr()` of values 0-15, i.e. control characters, and accumulated by
    repeated string concatenation.
    """
    lines = [
        "There is not sufficient coverage between the secrets to encrypt all possible bytes!",
        f"{len(missing)} missing nibble combination(s):",
    ]
    lines.extend(
        "  " + " ".join(f"0x{nibble:x}" for nibble in key)
        for key in missing[:MAX_REPORTED_COMBINATIONS]
    )
    if len(missing) > MAX_REPORTED_COMBINATIONS:
        lines.append(f"  ...and {len(missing) - MAX_REPORTED_COMBINATIONS} more")
    return "\n".join(lines)


def do_version(_args: argparse.Namespace, outfile: BinaryIO) -> int:
    outfile.write(
        f"Lenticrypt {VERSION}\nCryptosystem Version {ENCRYPTION_VERSION}\n{COPYRIGHT}\n".encode()
    )
    return 0


def _rng(args: argparse.Namespace) -> random.Random:
    """A CSPRNG by default; a reproducible generator only when `--seed` asks for one."""
    if args.seed is None:
        return default_rng()
    logger.warning(
        "--seed makes this ciphertext reproducible, and therefore predictable. Use it for testing, "
        "not for anything you need kept secret."
    )
    return seeded_rng(args.seed)


def do_encrypt(args: argparse.Namespace, outfile: BinaryIO) -> int:
    secrets = tuple(Path(secret).read_bytes() for secret, _plaintext in args.encrypt)
    # The level caps how far up the ladder we go; the adaptive choice drops lengths that these
    # particular secrets are too short to ever hit, which is most of them at realistic key sizes.
    lengths = select_nibble_gram_lengths(min(map(len, secrets)), len(secrets))[: args.level]
    logger.info(f"Indexing nibble-gram lengths {lengths}")
    with contextlib.ExitStack() as stack:
        callback = _progress_callback(args)
        if callback is not None:
            stack.enter_context(callback)
        substitution_alphabet = find_common_nibble_grams(
            secrets, nibble_gram_lengths=lengths, status_callback=callback
        )
    if len(substitution_alphabet[1]) < 16 ** len(secrets):
        message = (
            "There is not sufficient coverage between the secrets to encrypt all possible bytes!"
        )
        if not args.force_encrypt:
            logger.error(message)
            logger.info("To encrypt anyway, re-run with the `-f` option.")
            return 1
        logger.warning(message)
    del secrets

    with contextlib.ExitStack() as stack:
        callback = _progress_callback(args)
        if callback is not None:
            stack.enter_context(callback)
        # `filename=''` suppresses the gzip FNAME field: given only `fileobj`, gzip stores
        # `fileobj.name`, so the ciphertext carried the path it was written to, in cleartext.
        # `mtime=1` keeps the timestamp out too, so `--seed` gives byte-identical output.
        zipfile = stack.enter_context(
            gzip.GzipFile(fileobj=outfile, mode="wb", mtime=1, filename="")
        )
        encrypter = ENCRYPTERS[args.mode]
        plaintexts = tuple(
            stack.enter_context(Path(plaintext).open("rb")) for _secret, plaintext in args.encrypt
        )
        # Written as it is produced, so peak memory does not scale with the ciphertext.
        for chunk in encrypter(
            substitution_alphabet, plaintexts, status_callback=callback, rng=_rng(args)
        ).chunks():
            zipfile.write(chunk)
    return 0


def do_decrypt(args: argparse.Namespace, outfile: BinaryIO) -> int:
    secret_path, ciphertext_path = args.decrypt
    # auto_unzip accepts plain as well as gzipped ciphertexts; the previous `gzip.GzipFile(...)`
    # raised an uncaught BadGzipFile traceback at the user for anything not gzipped.
    with auto_unzip(ciphertext_path) as ciphertext, Path(secret_path).open("rb") as secret:
        outfile.writelines(decrypt_chunks(ciphertext, secret))
    return 0


def do_test(args: argparse.Namespace, _outfile: BinaryIO) -> int:
    secrets = tuple(Path(secret).read_bytes() for secret in args.test)
    with contextlib.ExitStack() as stack:
        callback = _progress_callback(args)
        if callback is not None:
            stack.enter_context(callback)
        substitution_alphabet = find_common_nibble_grams(
            secrets, nibble_gram_lengths=(1,), status_callback=callback, stop_when_sufficient=True
        )
    missing = missing_combinations(substitution_alphabet, len(secrets))
    if missing:
        logger.critical(_format_missing(missing))
        return 1
    logger.info("This set of secrets looks good!")
    return 0


def _select_action(
    args: argparse.Namespace,
) -> Callable[[argparse.Namespace, BinaryIO], int]:
    if args.version:
        return do_version
    if args.encrypt:
        return do_encrypt
    if args.decrypt:
        return do_decrypt
    return do_test


def main(argv: Sequence[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv
    args = build_parser().parse_args(argv[1:])
    configure_logging(args)

    with contextlib.ExitStack() as stack:
        if args.outfile is None or args.outfile == "-":
            # stdout is not ours to close; flushing is enough, and closing it discarded output
            # still buffered in the enclosing TextIOWrapper.
            outfile = cast("BinaryIO", getattr(sys.stdout, "buffer", sys.stdout))
            stack.callback(outfile.flush)
        else:
            outfile = cast("BinaryIO", stack.enter_context(Path(args.outfile).open("wb")))
        try:
            return _select_action(args)(args, outfile)
        except (KeyboardInterrupt, BrokenPipeError):
            # Die quietly; a stack trace here is noise, not information.
            return 1
        except LenticryptError as error:
            # Deliberately `error`, not `exception`: a LenticryptError means the *input* was bad,
            # so the message is the useful part and a traceback is noise.
            logger.error(str(error))  # noqa: TRY400
            return 1


if __name__ == "__main__":
    sys.exit(main())
