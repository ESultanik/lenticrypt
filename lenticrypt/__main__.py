import argparse
import gzip
import itertools
import logging
import random
import sys

from .lenticrypt import ENCRYPTION_VERSION, decrypt, find_common_nibble_grams, Encrypter, LengthChecksumEncrypter, DictionaryEncrypter, VERSION
from .logger import ColorFormatter, DEFAULT_FORMAT as DEFAULT_LOG_FORMAT
from .progress import ProgressBarCallback

logging.basicConfig(stream=sys.stderr, level=logging.INFO)
logger = logging.getLogger(name='lenticrypt')


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv

    copyright_message = "Copyright (C) 2012--2019, Evan A. Sultanik, Ph.D.  \nhttps://www.sultanik.com/\n"

    parser = argparse.ArgumentParser(
        description="A toy cryptosystem with provable plausible deniability.  " + copyright_message,
        prog="lenticrypt")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="append", nargs=2, type=argparse.FileType('rb'),
                       metavar=('secret', 'plaintext'),
                       help="encrypts the given plaintext file(s) into a single ciphertext using the given secret file(s).  Additional secret/plaintext pairs can be specified by providing the `-e` option multiple times.  For example, `-e secret1 plaintext1 -e secret2 plaintext2 -e secret3 plaintext3 ...`.  If the `-l` argument is used, any plaintext that is longer than the first one provided will be truncated.  Any plaintext that is shorter than the first one provided will be tail-padded with zeros.")
    group.add_argument("-d", "--decrypt", nargs=2, type=str, metavar=('secret', 'ciphertext'),
                       help="decrypts the ciphertext file using the given secret file")
    group.add_argument("-t", "--test", type=argparse.FileType('rb'), nargs="+", metavar=('secret'),
                       help="tests whether a given set of secrets have sufficient entropy to encrypt an equal number of plaintexts.  The exit code of the program is zero on success.  On failure, the missing byte combinations are printed to stdout.")

    parser.add_argument("-f", "--force-encrypt", action="store_true", default=False,
                        help="force encryption, even if the secrets have insufficient entropy to correctly encrypt the plaintexts")
    default_output = sys.stdout
    if hasattr(default_output, 'buffer'):
        # when running from unit tests, `sys.stdout` is a `FlushingStringIO` which has no `buffer` attribute
        default_output = default_output.buffer
    parser.add_argument("-o", "--outfile", nargs='?', type=argparse.FileType('wb'), default=default_output,
                        help="the output file (default to stdout)")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--same-length", action="store_true", default=False,
                            help="removes the header that is used to specify the length of the encrypted files.  The header solves the problem of having plaintexts of unequal length, so with this option enabled encryption might be lossy if the plaintexts are not the same length.  This option does slightly strengthen plausible deniability, but has the potential to produce very large ciphertexts.")
    mode_group.add_argument("--length-checksum", action="store_true", default=False,
                            help="encrypts the files with an encrypted file length checksum at slight expense to plausible deniability, however, it allows for correct decryption if the plaintexts are of different lengths.  This has the potential to produce very large ciphertexts.")
    mode_group.add_argument("--dictionary", action="store_true", default=True,
                            help="encrypts the files using both the file length checksum used with the `-c` option, but also with an index dictionary that can greatly reduce ciphertext size.  This is the default mode for encryption.")
    group.add_argument("-v", "--version", action="store_true", default=False, help="prints version information")
    parser.add_argument("-q", "--quiet", action="store_true", default=False, help="suppresses log messages; equivalent to `--log-level QUIET`")
    parser.add_argument('-l', '--log-level', type=str.upper, choices={'QUIET', 'CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'}, default='INFO', help="Set Lenticrypt's log level (default=INFO)")
    compression_group = parser.add_mutually_exclusive_group()
    compression_group.add_argument("-1", "--fast", action="store_true", default=False)
    compression_group.add_argument("-2", dest="two", action="store_true", default=False)
    compression_group.add_argument("-3", dest="three", action="store_true", default=False)
    compression_group.add_argument("-4", dest="four", action="store_true", default=True)
    compression_group.add_argument("-5", "--best", action="store_true", default=False,
                                   help="These options change the compression level used, with the -1 option being the fastest, with less compression, and the -5 option being the slowest, with best compression.  CPU and memory usage will increase exponentially as the compression level increases.  The default compression level is -4.")
    parser.add_argument("-s", "--seed", type=int, default=None,
                        help="seeds the random number generator to the given value")

    args = parser.parse_args(argv[1:])

    if args.quiet or args.log_level == 'QUIET':
        logger.setLevel(logging.CRITICAL)
        logger.propagate = False
        use_color = False
    else:
        logger.setLevel(getattr(logging, args.log_level))
        use_color = sys.stderr.isatty()
    if not logger.handlers:
        logger.propagate = False
        handler = logging.StreamHandler()
        handler.setFormatter(ColorFormatter(DEFAULT_LOG_FORMAT, use_color=use_color))
        logger.addHandler(handler)

    if args.seed is not None:
        random.seed(args.seed)

    try:
        if args.version:
            sys.stdout.write(f"Lenticrypt {VERSION}\nCryptosystem Version {ENCRYPTION_VERSION}\n{copyright_message}\n")
        elif args.encrypt:
            secrets = tuple(bytearray(s[0].read()) for s in args.encrypt)
            nibble_gram_lengths = [1, 2, 4, 8, 16]
            if args.fast:
                nibble_gram_lengths = nibble_gram_lengths[:1]
            elif args.two:
                nibble_gram_lengths = nibble_gram_lengths[:2]
            elif args.three:
                nibble_gram_lengths = nibble_gram_lengths[:3]
            elif args.four:
                nibble_gram_lengths = nibble_gram_lengths[:4]
            callback = None
            if not args.quiet and sys.stderr.isatty():
                callback = ProgressBarCallback()
            try:
                substitution_alphabet = find_common_nibble_grams(secrets, nibble_gram_lengths=nibble_gram_lengths,
                                                                 status_callback=callback)
            except (KeyboardInterrupt, SystemExit):
                # die gracefully, without a stacktrace
                return 1
            finally:
                if callback is not None:
                    callback.clear()
            if len(substitution_alphabet[1]) < 16 ** len(secrets):
                err_msg = 'There is not sufficient coverage between the certificates to encrypt all possible bytes!'
                if args.force_encrypt:
                    logger.warning(err_msg)
                else:
                    logger.error(err_msg)
                    logger.info('To suppress this error, re-run with the `-f` option.')
                    return 1
            # let the secret files be garbage collected, if needed:
            secrets = None
            callback = None
            if not args.quiet and sys.stderr.isatty():
                callback = ProgressBarCallback()
            try:
                with gzip.GzipFile(fileobj=args.outfile, mtime=1) as zipfile:
                    # mtime is set to 1 so that the output files are always identical if a random seed argument is provided
                    if args.same_length:
                        encrypter = Encrypter
                    elif args.length_checksum:
                        encrypter = LengthChecksumEncrypter
                    else:
                        encrypter = DictionaryEncrypter
                    zipfile.write(bytes(encrypter(substitution_alphabet, tuple(e[1] for e in args.encrypt),
                                          status_callback=callback)))
            except (KeyboardInterrupt, SystemExit):
                # die gracefully, without a stacktrace
                return 1
            finally:
                if callback is not None:
                    callback.clear()
        elif args.decrypt:
            try:
                with gzip.GzipFile(args.decrypt[1]) as ciphertext:
                    with open(args.decrypt[0], 'rb') as secret:
                        args.outfile.write(bytes(decrypt(ciphertext, secret)))
            except (KeyboardInterrupt, SystemExit):
                # die gracefully, without a stacktrace
                return 1
        elif args.test:
            secrets = tuple(s.read() for s in args.test)
            callback = None
            if not args.quiet and sys.stderr.isatty():
                callback = ProgressBarCallback()
            try:
                substitution_alphabet = find_common_nibble_grams(secrets, nibble_gram_lengths=(1,), status_callback=callback, stop_when_sufficient=True)
            except (KeyboardInterrupt, SystemExit):
                # die gracefully, without a stacktrace
                return 1
            finally:
                if callback is not None:
                    callback.clear()
            if len(substitution_alphabet[1]) < 16 ** len(secrets):
                message = "There is not sufficient coverage between the certificates to encrypt all possible bytes!\nMissing byte combinations:"
                for combination in itertools.product(*[range(16) for _ in range(len(secrets))]):
                    if tuple((c,) for c in combination) not in substitution_alphabet[1]:
                        message = f"{message}\n{tuple(chr(c) for c in combination)}"
                logger.critical(message)
                return 1
            else:
                logger.info("This set of secrets looks good!")
                return 0
        return 0
    finally:
        if args.encrypt:
            for e in args.encrypt:
                for encrypt_file in e:
                    encrypt_file.close()
        if args.outfile:
            if args.outfile != sys.stdout:
                args.outfile.close()
        if args.test:
            for test_file in args.test:
                test_file.close()


if __name__ == '__main__':
    exit(main())
