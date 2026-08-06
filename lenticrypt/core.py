import array
import itertools
import logging
import random
import struct

from collections import defaultdict
from io import BytesIO
from typing import Any, BinaryIO, Callable, Dict, Generator, List, Optional, Sequence, Tuple, Union

from .__about__ import __version__
from .exceptions import EncodingError, LenticryptError
from .iowrapper import get_length, IOWrappable, IOWrapper
from .utils import FrozenDict

__all__ = [
    "ENCRYPTION_VERSION",
    "MAX_ENCODE_VALUE",
    "VERSION",
    "BufferedNibbleGramReader",
    "CommonNibbleGramsTypeHint",
    "DictionaryEncrypter",
    "Encrypter",
    "LengthChecksumEncrypter",
    "NibbleGramTypeHint",
    "NibbleGramsTypeHint",
    "StatusCallbackTypeHint",
    "decode",
    "decrypt",
    "encode",
    "encoding_steps",
    "find_common_nibble_grams",
    "index_type_map",
    "is_power2",
    "read_nibble_grams",
    "read_nibbles",
]

logger = logging.getLogger(name="lenticrypt")

# The version of the ciphertext file format, independent of the package version: bumping one does
# not imply bumping the other. Prior releases conflated them by encoding this as the semver minor.
ENCRYPTION_VERSION: int = 3

VERSION: str = __version__

StatusCallbackTypeHint = Optional[Callable[[int, int, str], Any]]


def is_power2(num):
    """tests if a number is a power of two"""
    return num != 0 and ((num & (num - 1)) == 0)


def read_nibbles(byte_array: Sequence[int]) -> Generator[int, None, None]:
    for b in byte_array:
        yield (b & 0b11110000) >> 4
        yield b & 0b00001111


NibbleGramTypeHint = Generator[bytes, None, None]


def read_nibble_grams(byte_array: Sequence[int], length: int = 1) -> NibbleGramTypeHint:
    if not is_power2(length):
        raise ValueError(f"length must be a power of two; received {length}")

    return (
        bytes(ng)
        for ng in zip(
            *(
                itertools.islice(nibbles, i, None)
                for i, nibbles in enumerate(itertools.tee(read_nibbles(byte_array), length))
            )
        )
    )


NibbleGramsTypeHint = Dict[Tuple[bytes, ...], array.array]
CommonNibbleGramsTypeHint = Dict[int, NibbleGramsTypeHint]


def find_common_nibble_grams(
    certificates: Sequence[Sequence[int]],
    nibble_gram_lengths=(1, 2, 4, 8, 16),
    status_callback: StatusCallbackTypeHint = None,
    stop_when_sufficient: bool = False,
) -> CommonNibbleGramsTypeHint:
    all_nibbles: CommonNibbleGramsTypeHint = {}  # maps a nibble value to a common index
    min_cert_length = min(len(c) for c in certificates)
    for nibble_gram_length in nibble_gram_lengths:
        nibbles: NibbleGramsTypeHint = defaultdict(lambda: array.array("L"))
        all_nibbles[nibble_gram_length] = nibbles
        range_max = min_cert_length * 2 - nibble_gram_length + 1
        for index, pair in enumerate(
            zip(*(read_nibble_grams(c, nibble_gram_length) for c in certificates))
        ):
            nibbles[pair].append(index)
            if stop_when_sufficient and len(nibbles) >= (16 * nibble_gram_length) ** len(
                certificates
            ):
                return all_nibbles
            if status_callback is not None:
                status_callback(
                    index, range_max, "Building Index for %s-nibble-grams" % nibble_gram_length
                )
    return all_nibbles


READ_BLOCK_BYTES = 4096

# The block header allocates four bits to `length - 1`, so grams longer than this cannot be encoded.
MAX_NIBBLE_GRAM_LENGTH = 16

# Distinct unencodable gram tuples to name in the log before falling back to a bare count.
MAX_REPORTED_UNENCODABLE = 16

# Report progress every this many consumed nibbles, rather than on every single one.
PROGRESS_INTERVAL_NIBBLES = 1024


class BufferedNibbleGramReader:
    """Reads a byte stream as a stream of nibbles, with lookahead.

    `peek_nibbles(length)` returns either exactly `length` nibbles or `None`. That guarantee is what
    the encrypters rely on: previously `has_nibbles` appended whatever a short read produced and
    returned `True` regardless, so `peek_nibbles` could hand back fewer nibbles than asked for.
    """

    def __init__(self, stream: BinaryIO):
        self.stream = stream
        self._buffer: Optional[bytearray] = bytearray()
        self.has_nibbles(1)

    def get_nibbles(self, length: int) -> Optional[bytes]:
        """Consumes and returns `length` nibbles, or returns `None` without consuming anything."""
        nibbles = self.peek_nibbles(length)
        if nibbles is not None and self._buffer is not None:
            del self._buffer[:length]
        return nibbles

    def peek_nibbles(self, length: int) -> Optional[bytes]:
        """Returns exactly `length` nibbles without consuming them, or `None` if unavailable."""
        if not self.has_nibbles(length):
            return None
        # has_nibbles() only returns True with a live buffer holding at least `length` nibbles; the
        # re-check keeps that provable rather than asserted, since asserts vanish under -O.
        buffer = self._buffer
        return None if buffer is None else bytes(buffer[:length])

    def has_nibbles(self, length: int) -> bool:
        """Whether `length` nibbles can be supplied, reading more of the stream if needed."""
        if self._buffer is None:
            return False
        # Keep reading until we genuinely have enough. A short read means the stream is nearly
        # exhausted, not that the request can be satisfied.
        while len(self._buffer) < length:
            block = self.stream.read(max(READ_BLOCK_BYTES, (length - len(self._buffer) + 1) // 2))
            if not block:
                if not self._buffer:
                    # Nothing buffered and nothing left to read: this reader is finished. `None` is
                    # the end-of-stream sentinel that `eof()` reports.
                    self._buffer = None
                return False
            for byte in block:
                self._buffer.append((byte & 0b11110000) >> 4)
                self._buffer.append(byte & 0b00001111)
        return True

    def eof(self) -> bool:
        """Whether the stream is exhausted *and* nothing remains buffered."""
        return self._buffer is None

    def __bool__(self) -> bool:
        return not self.eof()


# block header, 8 bits:
# MSB -> X X X X X X X X <- LSB
#                 |-----| <-- index_bytes - 1 (since index_bytes is always greater than zero)
#         |-------| <-- length - 1 (since length is always greater than zero)
#       |-| <-- If 1, then the following 7 bits are a filetype version number and the following blocks are the encrypted 8 bytes encoding the length of the file
class Encrypter(object):
    def __init__(
        self,
        substitution_alphabet: CommonNibbleGramsTypeHint,
        to_encrypt: Sequence[BinaryIO],
        status_callback: StatusCallbackTypeHint = None,
    ):
        self.substitution_alphabet = substitution_alphabet
        self.to_encrypt = to_encrypt
        self.sorted_lengths = sorted(substitution_alphabet.keys(), reverse=True)
        if self.sorted_lengths and self.sorted_lengths[0] > MAX_NIBBLE_GRAM_LENGTH:
            # Validated once here rather than per block: the block header only allocates four bits
            # for the length, so longer grams cannot be represented at all.
            message = (
                f"Lenticrypt's encoding supports nibble-gram lengths up to "
                f"{MAX_NIBBLE_GRAM_LENGTH}; got {self.sorted_lengths[0]}"
            )
            raise EncodingError(message)
        self.status_callback = status_callback
        self.buffer_lengths = [get_length(b) for b in self.to_encrypt]
        self._unencodable: set[Tuple[bytes, ...]] = set()
        self._unencodable_count = 0

    def get_header(self):
        return iter([])

    def is_incomplete(self, buffers) -> bool:
        return bool(buffers[0])

    def total_nibbles(self) -> int:
        """Total nibbles this encrypter will consume, as an exact progress denominator.

        Replaces `get_max_length()`, whose result was multiplied by a guess at the number of
        attempts per byte, so progress bars over- or under-shot depending on the inputs.
        """
        return self.buffer_lengths[0] * 2

    def pad_nibble_gram(self, buffer_index: int, length: int) -> Optional[bytes]:
        """The substitute gram for a plaintext that has run out, or `None` to stop encrypting.

        Only ever called for a reader that is genuinely at end of stream. Returning `None` makes the
        gram unusable at this length, which is how the base class stops at the first plaintext's
        length.
        """
        return b"\0" * length if buffer_index > 0 else None

    def _grams_at(
        self, readers: Sequence[BufferedNibbleGramReader], length: int
    ) -> Optional[Tuple[bytes, ...]]:
        """Every reader's nibble-gram at `length`, or `None` if they cannot all supply one.

        A reader that still holds real data but fewer than `length` nibbles yields `None` here, so
        the caller falls back to a shorter length. Padding it instead would overwrite live
        plaintext -- which is precisely how ciphertexts used to be corrupted.
        """
        grams = []
        for index, reader in enumerate(readers):
            gram = reader.peek_nibbles(length)
            if gram is None:
                if not reader.eof():
                    return None
                gram = self.pad_nibble_gram(index, length)
                if gram is None:
                    return None
            grams.append(gram)
        return tuple(grams)

    def can_encode(self, grams: Tuple[bytes, ...], length: int) -> bool:
        """Whether this gram tuple can be represented as a ciphertext block."""
        return grams in self.substitution_alphabet[length]

    def encode_block(self, grams: Tuple[bytes, ...], length: int) -> bytes:
        """Encodes one accepted gram tuple as a ciphertext block."""
        index = random.choice(self.substitution_alphabet[length][grams])
        if index < 256:
            index_bytes, index_type = 1, "B"  # unsigned char
        elif index < 65536:
            index_bytes, index_type = 2, "H"  # unsigned short
        elif index < 4294967296:
            index_bytes, index_type = 4, "L"  # unsigned long
        else:
            index_bytes, index_type = 8, "Q"  # unsigned long long
        block_header = ((length - 1) << 3) | (index_bytes - 1)
        return struct.pack("<B" + index_type, block_header, index)

    def _warn_unencodable(self, grams: Tuple[bytes, ...]) -> None:
        """Warns once per distinct gram tuple, so weak secrets cannot flood the log."""
        self._unencodable_count += 1
        if grams in self._unencodable or len(self._unencodable) >= MAX_REPORTED_UNENCODABLE:
            return
        self._unencodable.add(grams)
        logger.warning(
            f"There is insufficient entropy in the input secrets to encode the byte pair "
            f"{grams!r}! The resulting ciphertext will not decrypt to the correct plaintext."
        )

    def consume_grams(
        self, readers: Sequence[BufferedNibbleGramReader], phase: str
    ) -> Generator[Tuple[int, Tuple[bytes, ...]], None, None]:
        """Walks the plaintexts in lockstep, yielding each `(length, grams)` that can be encoded.

        This is the only place nibbles are consumed, so it is structurally impossible to emit a
        block for nibbles that were not consumed -- the desynchronisation that corrupted output.
        Longest gram lengths are tried first; a length that cannot be represented falls back to a
        shorter one, and at length 1 the nibbles are consumed with a warning so that the walk always
        makes progress.
        """
        total = self.total_nibbles()
        consumed = 0
        # Per-pass tallies. The dictionary pass and the encrypt pass each walk the plaintexts, so
        # without resetting, the second pass reports the first one's grams again.
        self._unencodable.clear()
        self._unencodable_count = 0
        while self.is_incomplete(readers):
            for length in self.sorted_lengths:
                grams = self._grams_at(readers, length)
                if grams is None:
                    continue
                encodable = self.can_encode(grams, length)
                if not encodable and length != 1:
                    continue
                for reader in readers:
                    reader.get_nibbles(length)
                if encodable:
                    yield length, grams
                else:
                    self._warn_unencodable(grams)
                consumed += length
                if self.status_callback is not None and consumed % PROGRESS_INTERVAL_NIBBLES == 0:
                    self.status_callback(consumed, total, phase)
                break
            else:
                # No length made progress. Normally that means `peek_nibbles` has only just
                # discovered end of stream -- exhaustion is detected lazily, on the read that fails,
                # so `is_incomplete` can still have been true on entry. Re-test it and stop cleanly
                # if we are genuinely finished; otherwise the walk really is stuck.
                if self.is_incomplete(readers):  # pragma: no cover - guarded invariant
                    message = (
                        "Unable to encode at any nibble-gram length while plaintext remains. "
                        "Length 1 should always consume; please report this as a bug."
                    )
                    raise LenticryptError(message)
                break
        # Only summarise when there was more than the individually reported grams to report.
        if self._unencodable_count > len(self._unencodable):
            logger.warning(
                f"{self._unencodable_count} nibble-gram(s) in total could not be encoded during "
                f"{phase.lower()}; the ciphertext will not decrypt to the correct plaintext."
            )

    def __iter__(self) -> Generator[int, None, None]:
        yield from self.get_header()
        readers = [BufferedNibbleGramReader(stream) for stream in self.to_encrypt]
        for length, grams in self.consume_grams(readers, "Encrypting"):
            yield from self.encode_block(grams, length)


class LengthChecksumEncrypter(Encrypter):
    def get_encryption_version(self):
        return 2

    def is_incomplete(self, buffers) -> bool:
        return any(not b.eof() for b in buffers)

    def total_nibbles(self) -> int:
        return max(self.buffer_lengths) * 2

    def pad_nibble_gram(self, buffer_index: int, length: int) -> Optional[bytes]:  # noqa: ARG002
        """Pads every exhausted plaintext with random nibbles, regardless of which one it is.

        Safe because the length header lets decryption truncate, and random padding is better for
        deniability than zeros. Only reached for readers genuinely at end of stream -- padding one
        that still held data is what corrupted plaintexts.
        """
        return bytes(random.randint(0, 15) for _ in range(length))

    def get_header(self):
        block_header = (
            0b10000000 | self.get_encryption_version()
        )  # the magic length checksum bit and filetype version number
        yield block_header
        lengths = tuple(BytesIO(struct.pack("<Q", get_length(l))) for l in self.to_encrypt)
        try:
            yield from iter(Encrypter(self.substitution_alphabet, lengths, status_callback=None))
        finally:
            for length in lengths:
                length.close()


encoding_steps = [
    (0b01111111, 0),
    (0b00111111, 0b10000000),
    (0b00011111, 0b11000000),
    (0b00001111, 0b11100000),
    (0b00000111, 0b11110000),
    (0b00000011, 0b11111000),
    (0b00000001, 0b11111100),
]

MAX_ENCODE_VALUE = (
    2 ** (8 * (len(encoding_steps) - 1))
    + (encoding_steps[-1][0] << (8 * (len(encoding_steps) - 1)))
    - 1
)


def encode(n: int) -> bytearray:
    orig_n = n
    ret = bytearray([n & 0b11111111])
    for test, mask in encoding_steps:
        if n <= test:
            ret[0] = ret[0] | mask
            return ret
        n >>= 8
        ret = bytearray([n & 0b11111111]) + ret
    raise Exception(
        f"Integer {orig_n} is too big to encode!  The biggest value supported is {MAX_ENCODE_VALUE}."
    )


def decode(byte_array: Union[bytes, bytearray, BinaryIO]) -> Optional[int]:
    to_close = None
    if isinstance(byte_array, bytes) or isinstance(byte_array, bytearray):
        byte_array = BytesIO(byte_array)
        to_close = byte_array
    try:
        num_trailing_bytes = 0
        raw_byte = byte_array.read(1)
        if len(raw_byte) < 1:
            return None
        byte: int = raw_byte[0]
        # remove everything to the left of the first zero:
        if not (byte & 0b10000000):
            pass
        elif not (byte & 0b01000000):
            byte = byte & 0b00111111
            num_trailing_bytes = 1
        elif not (byte & 0b00100000):
            byte = byte & 0b00011111
            num_trailing_bytes = 2
        elif not (byte & 0b00010000):
            byte = byte & 0b00001111
            num_trailing_bytes = 3
        elif not (byte & 0b00001000):
            byte = byte & 0b00000111
            num_trailing_bytes = 4
        elif not (byte & 0b00000100):
            byte = byte & 0b00000011
            num_trailing_bytes = 5
        elif not (byte & 0b00000010):
            byte = byte & 0b00000001
            num_trailing_bytes = 6
        n: int = byte
        for i in range(num_trailing_bytes):
            n <<= 8
            raw_byte = byte_array.read(1)
            if len(raw_byte) < 1:
                raise Exception("Error: expected another byte in the stream!")
            byte = raw_byte[0]
            n |= byte
        return n
    finally:
        if to_close is not None:
            to_close.close()


# An encrypter for version 3 of the file spec.
class DictionaryEncrypter(LengthChecksumEncrypter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dictionary: Dict[Tuple[bytes, ...], int] = {}
        self.dictionary_items: List[Tuple[bytes, ...]] = []
        # `can_encode` consults the substitution alphabet while building and the dictionary
        # afterwards; an explicit flag rather than testing the dictionary for emptiness.
        self._dictionary_built = False
        self.build_dictionary()
        self._dictionary_built = True

    def get_encryption_version(self):
        return 3

    def build_dictionary(self):
        """Counts which nibble-gram tuples the plaintexts use, most frequent first.

        Driven by the shared walk, which supplies the length-1 fallback this pass lacked: with its
        own loop, a gram the secrets could not encode consumed nothing and the walk spun forever --
        exactly the `-f/--force-encrypt` case.
        """
        readers = [BufferedNibbleGramReader(stream) for stream in self.to_encrypt]
        hits: Dict[Tuple[bytes, ...], int] = {}
        for _length, grams in self.consume_grams(readers, "Building Dictionary"):
            hits[grams] = hits.get(grams, 0) + 1
        # Every single-nibble gram the secrets can encode needs an entry, so encryption can always
        # fall back to length 1. Weight 0 keeps observed grams ahead of these fillers.
        #
        # Only grams actually in the substitution alphabet are added. Adding all 16**n
        # unconditionally meant `get_header` later looked up a gram the alphabet lacked; because the
        # alphabet is a defaultdict, that silently inserted an empty array and then raised
        # IndexError on [0]. Iterated lazily rather than materialised as a set: 16**n is 16.7M
        # tuples for 6 secrets.
        encodable_single_grams = self.substitution_alphabet.get(1, {})
        for gram in itertools.product(
            *([bytes([nibble]) for nibble in range(16)] for _ in range(len(self.to_encrypt)))
        ):
            if gram not in hits and gram in encodable_single_grams:
                hits[gram] = 0
        # Sorted over the mapping rather than a set difference: iteration order of a set of tuples
        # of `bytes` varies with PYTHONHASHSEED, so dictionary indices differed between runs and
        # defeated `--seed` reproducibility. The gram itself breaks ties deterministically.
        self.dictionary_items = sorted(hits, key=lambda gram: (-hits[gram], gram))
        self.dictionary = {gram: index for index, gram in enumerate(self.dictionary_items)}
        # reset the files back to their first bytes
        for e in self.to_encrypt:
            e.seek(0)

    def can_encode(self, grams: Tuple[bytes, ...], length: int) -> bool:
        # While encrypting, the dictionary is the authority; while building it, the base class's
        # substitution-alphabet check is used instead.
        if self._dictionary_built:
            return grams in self.dictionary
        return super().can_encode(grams, length)

    def encode_block(self, grams: Tuple[bytes, ...], length: int) -> bytes:
        return encode(self.dictionary[grams])

    def get_header(self):
        yield from super().get_header()
        # The dictionary itself: one (certificate offset, gram length) pair per entry.
        yield from iter(encode(len(self.dictionary)))
        for grams in self.dictionary_items:
            gram_length = len(grams[0])
            # An explicit check rather than `assert`, which vanishes under -O. build_dictionary only
            # admits grams the alphabet can encode, so reaching this is a bug, not bad input.
            offsets = self.substitution_alphabet.get(gram_length, {}).get(grams)
            if gram_length > 255 or not offsets:
                message = (
                    f"Cannot write a dictionary entry for {grams!r}: the substitution alphabet has "
                    f"no offset for it at length {gram_length}. Please report this as a bug."
                )
                raise LenticryptError(message)
            yield from iter(encode(offsets[0]))
            yield gram_length


index_type_map = FrozenDict({1: "B", 2: "H", 4: "L", 8: "Q"})


def _decrypt_dictionary(stream, file_length, cert):
    # read the dictionary index:
    dictionary_length = decode(stream)
    dictionary = []
    for i in range(dictionary_length):
        index = decode(stream)
        b = stream.read(1)
        if len(b) < 1:
            raise Exception("Unexpected end of file while decoding dictionary!")
        length = b[0]
        dictionary.append((index, length))
    last_nibble = None
    num_bytes = 0
    while num_bytes < file_length:
        dict_index = decode(stream)
        if dict_index >= len(dictionary):
            raise Exception(
                f"Invalid dictionary index {dict_index}!  Maximum valid index is {len(dictionary) - 1}."
            )
        index, length = dictionary[dict_index]
        if length == 1:
            if last_nibble is None:
                last_nibble = cert[index] << 4
            else:
                yield last_nibble | cert[index]
                last_nibble = None
                num_bytes += 1
        else:
            nibbles = cert[index : index + length]
            if last_nibble is not None:
                yield last_nibble | nibbles[0]
                num_bytes += 1
                last_nibble = nibbles[-1] << 4
                nibbles = nibbles[1:-1]
            for index in range(0, len(nibbles), 2):
                yield (nibbles[index] << 4) | nibbles[index + 1]
                num_bytes += 1


def decrypt(
    ciphertext: IOWrappable,
    certificate: Optional[IOWrappable],
    cert: Optional[bytearray] = None,
    file_length: Optional[int] = None,
) -> Generator[int, None, None]:
    # the file format is specified in a comment at the top of the encrypt(...) function above.
    if cert is None:
        cert = bytearray()
        with IOWrapper(certificate) as stream:
            while True:
                b = stream.read(1)
                if not b:
                    break
                b = b[0] & 0b11111111
                cert.append((b & 0b11110000) >> 4)
                cert.append(b & 0b00001111)
    with IOWrapper(ciphertext) as stream:
        last_nibble = None
        num_bytes = 0
        while True:
            header = stream.read(1)
            if not header:
                break
            header = struct.unpack("<B", header)[0]
            is_length_header = header & 0b10000000
            if is_length_header:
                version = header & 0b01111111
                logger.info(f"Found length header. File format version is {version}")
                if version > ENCRYPTION_VERSION:
                    logger.warning(
                        f"This ciphertext appears to have been encrypted with a newer version of the cryptosystem (version {(version / 10.0)!s})."
                    )
                # the next 8 encrypted bytes encode the length of the plaintext
                raw_length = bytearray(decrypt(stream, None, cert=cert, file_length=8))
                file_length = struct.unpack("<Q", raw_length)[0]
                logger.info(f"Plaintext file length is {file_length} bytes")
                if version == 3:
                    yield from _decrypt_dictionary(stream, file_length, cert)
                    return
                continue
            index_bytes = (header & 0b00000111) + 1
            if index_bytes not in index_type_map:
                raise Exception(
                    f"Invalid block header: Received an invalid index byte length of {index_bytes!s} bytes!"
                )
            length = ((header >> 3) & 0b00001111) + 1
            index = stream.read(index_bytes)
            if not index:
                break
            n = struct.unpack("<" + index_type_map[index_bytes], index)[0]
            if n >= len(cert):
                logger.warning(
                    f"Decrypted invalid certificate index {n} (maximum value is {len(cert) - 1})"
                )
                if last_nibble is not None:
                    yield last_nibble
                    num_bytes += 1
                    if file_length is not None and num_bytes >= file_length:
                        return
                    last_nibble = None
                    length -= 1
                for i in range(length):
                    yield 0
                    num_bytes += 1
                    if file_length is not None and num_bytes >= file_length:
                        return
            elif length == 1:
                if last_nibble is None:
                    last_nibble = cert[n] << 4
                else:
                    yield last_nibble | cert[n]
                    last_nibble = None
                    num_bytes += 1
                    if file_length is not None and num_bytes >= file_length:
                        return
            else:
                nibbles = cert[n : n + length]
                if last_nibble is not None:
                    yield last_nibble | nibbles[0]
                    num_bytes += 1
                    last_nibble = None
                    nibbles = nibbles[1:]
                    if file_length is not None and num_bytes >= file_length:
                        return
                for index in range(0, len(nibbles), 2):
                    if index == len(nibbles) - 1:
                        last_nibble = nibbles[index] << 4
                    else:
                        yield (nibbles[index] << 4) | nibbles[index + 1]
                        num_bytes += 1
                        if file_length is not None and num_bytes >= file_length:
                            return
