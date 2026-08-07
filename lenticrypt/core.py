import array
import gzip
import itertools
import logging
import random
import struct
import zlib
from collections.abc import Generator, Iterator, Sequence
from io import BytesIO
from typing import IO, BinaryIO, TypeAlias

from .__about__ import __version__
from .exceptions import (
    EncodingError,
    LenticryptError,
    MalformedCiphertextError,
    UnsupportedVersionError,
)
from .iowrapper import IOWrappable, IOWrapper, get_length
from .progress import StatusCallback
from .rng import default_rng
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
    "decrypt_chunks",
    "encode",
    "encoding_steps",
    "find_common_nibble_grams",
    "index_type_map",
    "is_power2",
    "nibbles_of",
    "pack_grams",
    "read_nibble_grams",
    "read_nibbles",
    "select_nibble_gram_lengths",
    "unpack_gram_length",
]

logger = logging.getLogger(name="lenticrypt")

# The block header allocates four bits to `length - 1`, so longer grams cannot be encoded.
MAX_NIBBLE_GRAM_LENGTH = 16

# Certificate offsets are stored as unsigned 32-bit ints. `array('L')` is *native* width -- 8 bytes
# here, 4 on Windows -- so it was both platform-dependent and twice the size needed. The 'L' in
# `index_type_map` is correct as-is: struct's `<` prefix selects standard sizes, where L is 4.
OFFSET_TYPECODE = "I"

# Report progress every 1024 offsets rather than on every one.
PROGRESS_MASK = 0x3FF

# Default granularity for the chunked encrypt and decrypt paths.
CHUNK_SIZE = 1 << 16

# The version of the ciphertext file format, independent of the package version: bumping one does
# not imply bumping the other. Prior releases conflated them by encoding this as the semver minor.
ENCRYPTION_VERSION: int = 3

VERSION: str = __version__

#: A progress reporter, or None for silence. `progress.StatusCallback` is the structural
#: contract; the alias is kept because it is part of the published surface.
StatusCallbackTypeHint: TypeAlias = StatusCallback | None


def is_power2(num: int) -> bool:
    """Whether `num` is a power of two."""
    return num != 0 and ((num & (num - 1)) == 0)


# Translation tables that map a byte to its high and low nibble, so a whole buffer can be expanded
# with two C-level `bytes.translate` calls instead of a per-byte Python loop.
_HIGH_NIBBLES = bytes(b >> 4 for b in range(256))
_LOW_NIBBLES = bytes(b & 0x0F for b in range(256))


def nibbles_of(data: bytes) -> bytes:
    """Expands `data` into one nibble per byte, high nibble first."""
    expanded = bytearray(len(data) * 2)
    expanded[0::2] = data.translate(_HIGH_NIBBLES)
    expanded[1::2] = data.translate(_LOW_NIBBLES)
    return bytes(expanded)


def read_nibbles(byte_array: Sequence[int]) -> Generator[int, None, None]:
    yield from nibbles_of(bytes(byte_array))


#: A stream of nibble-grams, one per starting offset.
NibbleGramTypeHint: TypeAlias = Iterator[bytes]


def read_nibble_grams(byte_array: Sequence[int], length: int = 1) -> NibbleGramTypeHint:
    """Yields every `length`-nibble window of `byte_array`, one nibble apart."""
    if not is_power2(length):
        message = f"length must be a power of two; received {length}"
        raise ValueError(message)
    nibbles = nibbles_of(bytes(byte_array))
    return (nibbles[i : i + length] for i in range(len(nibbles) - length + 1))


# The index maps a *packed* gram key to the certificate offsets where it occurs. The key interleaves
# the certificates' nibbles -- key[j::num_secrets] is certificate j's gram -- so it can be produced
# by a single slice of one interleaved buffer, rather than one slice per certificate plus a concat.
# Measured ~2.2x faster to build than concatenation, at the same memory.
#: Packed gram key -> the certificate offsets at which it occurs.
NibbleGramsTypeHint: TypeAlias = dict[bytes, "array.array[int]"]
#: Nibble-gram length -> that length's index.
CommonNibbleGramsTypeHint: TypeAlias = dict[int, NibbleGramsTypeHint]

# A length is worth indexing if its keyspace is small in absolute terms...
ABSOLUTE_CHEAP_KEYSPACE = 1 << 16
# ...or if the certificates supply enough offsets to populate a useful fraction of it.
MIN_OFFSETS_PER_KEY = 2


def pack_grams(grams: Sequence[bytes]) -> bytes:
    """Packs one gram per certificate into a single index key, matching the interleaved layout."""
    # strict: every certificate must contribute a gram of the same length, by construction.
    return bytes(itertools.chain.from_iterable(zip(*grams, strict=True)))


def unpack_gram_length(key: bytes, num_secrets: int) -> int:
    """The nibble-gram length a packed key represents."""
    return len(key) // num_secrets


def select_nibble_gram_lengths(
    min_cert_length: int, num_secrets: int, max_length: int = MAX_NIBBLE_GRAM_LENGTH
) -> tuple[int, ...]:
    """Chooses which nibble-gram lengths are worth indexing for these certificates.

    A length-L hit needs the grams from *every* certificate to match at the same offset, so the
    keyspace is 16**(L*num_secrets) while the certificates supply only 2*min_cert_length offsets.
    Past a point the index is one unique key per offset: pure memory, never a hit. Measured with two
    256 KiB certificates, lengths 4, 8 and 16 held 1.57M keys between them, none reused, and were
    used for 0% of blocks -- roughly 75% of the index for nothing.

    Length 1 is always included; without it no byte can be encoded at all.
    """
    offsets = 2 * min_cert_length
    lengths = []
    for length in (1, 2, 4, 8, 16):
        if length > max_length:
            break
        keyspace = 16 ** (length * num_secrets)
        cheap = keyspace <= ABSOLUTE_CHEAP_KEYSPACE
        useful = offsets >= MIN_OFFSETS_PER_KEY * keyspace
        if length == 1 or cheap or useful:
            lengths.append(length)
        else:
            # Longer grams only have larger keyspaces, so nothing after this qualifies either.
            break
    return tuple(lengths)


def find_common_nibble_grams(
    certificates: Sequence[Sequence[int]],
    nibble_gram_lengths: Sequence[int] | None = None,
    status_callback: StatusCallbackTypeHint = None,
    stop_when_sufficient: bool = False,
) -> CommonNibbleGramsTypeHint:
    """Indexes the offsets at which the certificates share each nibble-gram combination.

    Args:
        certificates: The secrets to index.
        nibble_gram_lengths: Lengths to index. Defaults to `select_nibble_gram_lengths`, which drops
            lengths too long to ever be hit for these certificates.
        status_callback: Progress reporter.
        stop_when_sufficient: Stop indexing a length once every combination has been seen.

    Returns:
        A mapping of nibble-gram length to a mapping of packed gram key to certificate offsets.
    """
    num_secrets = len(certificates)
    min_cert_length = min(len(c) for c in certificates)
    if nibble_gram_lengths is None:
        nibble_gram_lengths = select_nibble_gram_lengths(min_cert_length, num_secrets)
    expanded = [nibbles_of(bytes(c)) for c in certificates]
    total_nibbles = min(len(n) for n in expanded)
    # One interleaved buffer, so a gram key is a single slice. Transient: 2*num_secrets*cert_size,
    # which is megabytes next to an index measured in gigabytes.
    interleaved = bytearray(total_nibbles * num_secrets)
    for secret, nibbles in enumerate(expanded):
        interleaved[secret::num_secrets] = nibbles[:total_nibbles]
    interleaved = bytes(interleaved)
    del expanded

    all_nibbles: CommonNibbleGramsTypeHint = {}
    for nibble_gram_length in nibble_gram_lengths:
        nibbles_index: NibbleGramsTypeHint = {}
        all_nibbles[nibble_gram_length] = nibbles_index
        # 16**(L*N) is the true number of distinct combinations; the previous
        # `(16*L)**N` was correct only for L=1, by coincidence.
        sufficient = 16 ** (nibble_gram_length * num_secrets)
        width = nibble_gram_length * num_secrets
        range_max = total_nibbles - nibble_gram_length + 1
        for index in range(range_max):
            start = index * num_secrets
            key = interleaved[start : start + width]
            offsets = nibbles_index.get(key)
            if offsets is None:
                nibbles_index[key] = offsets = array.array(OFFSET_TYPECODE)
            offsets.append(index)
            if stop_when_sufficient and len(nibbles_index) >= sufficient:
                break
            # Throttled: this used to fire once per nibble offset, i.e. millions of Python calls
            # plus float arithmetic, all of it invisible work when nothing is watching.
            if status_callback is not None and not index & PROGRESS_MASK:
                status_callback(
                    index, range_max, f"Building Index for {nibble_gram_length}-nibble-grams"
                )
    return all_nibbles


READ_BLOCK_BYTES = 4096

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

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream
        self._buffer: bytearray | None = bytearray()
        self.has_nibbles(1)

    def get_nibbles(self, length: int) -> bytes | None:
        """Consumes and returns `length` nibbles, or returns `None` without consuming anything."""
        nibbles = self.peek_nibbles(length)
        if nibbles is not None and self._buffer is not None:
            del self._buffer[:length]
        return nibbles

    def peek_nibbles(self, length: int) -> bytes | None:
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


# Block header, 8 bits:
#
#     MSB -> X X X X X X X X <- LSB
#                     |-----| index_bytes - 1  (index_bytes is always at least one)
#             |-------| length - 1             (length is always at least one)
#           |-| length-header flag
#
# When the flag is set, the low seven bits are a file format version number, and the blocks that
# follow encode the eight bytes of the plaintext length rather than plaintext content.
class Encrypter:
    def __init__(
        self,
        substitution_alphabet: CommonNibbleGramsTypeHint,
        to_encrypt: Sequence[BinaryIO],
        status_callback: StatusCallbackTypeHint = None,
        rng: random.Random | None = None,
    ) -> None:
        # Explicit rather than module-level `random`, so the caller decides between a CSPRNG and a
        # seeded generator, and so nothing else in the process can perturb the ciphertext.
        self.rng = default_rng() if rng is None else rng
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
        self._unencodable: set[tuple[bytes, ...]] = set()
        self._unencodable_count = 0

    def get_header(self) -> Iterator[bytes]:
        """Yields the ciphertext header, as whole chunks."""
        return iter(())

    def is_incomplete(self, buffers: Sequence["BufferedNibbleGramReader"]) -> bool:
        return bool(buffers[0])

    def total_nibbles(self) -> int:
        """Total nibbles this encrypter will consume, as an exact progress denominator.

        Replaces `get_max_length()`, whose result was multiplied by a guess at the number of
        attempts per byte, so progress bars over- or under-shot depending on the inputs.
        """
        return self.buffer_lengths[0] * 2

    def pad_nibble_gram(self, buffer_index: int, length: int) -> bytes | None:
        """The substitute gram for a plaintext that has run out, or `None` to stop encrypting.

        Only ever called for a reader that is genuinely at end of stream. Returning `None` makes the
        gram unusable at this length, which is how the base class stops at the first plaintext's
        length.
        """
        return b"\0" * length if buffer_index > 0 else None

    def _grams_at(
        self, readers: Sequence[BufferedNibbleGramReader], length: int
    ) -> tuple[bytes, ...] | None:
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

    def can_encode(self, key: bytes, length: int) -> bool:
        """Whether this packed gram key can be represented as a ciphertext block."""
        return key in self.substitution_alphabet[length]

    def encode_block(self, key: bytes, length: int) -> bytes:
        """Encodes one accepted gram key as a ciphertext block."""
        index = self.rng.choice(self.substitution_alphabet[length][key])
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

    def _warn_unencodable(self, grams: tuple[bytes, ...]) -> None:
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
    ) -> Generator[tuple[int, bytes], None, None]:
        """Walks the plaintexts in lockstep, yielding each `(length, grams)` that can be encoded.

        This is the only place nibbles are consumed, so it is structurally impossible to emit a
        block for nibbles that were not consumed -- the desynchronization that corrupted output.
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
                # Packed once per position. It used to be packed twice per emitted block, once for
                # the membership test and again to look up the value.
                key = pack_grams(grams)
                encodable = self.can_encode(key, length)
                if not encodable and length != 1:
                    continue
                for reader in readers:
                    reader.get_nibbles(length)
                if encodable:
                    yield length, key
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
        # Only summarize when there was more than the individually reported grams to report.
        if self._unencodable_count > len(self._unencodable):
            logger.warning(
                f"{self._unencodable_count} nibble-gram(s) in total could not be encoded during "
                f"{phase.lower()}; the ciphertext will not decrypt to the correct plaintext."
            )

    def blocks(self) -> Iterator[bytes]:
        """Yields the ciphertext as whole blocks, header first.

        The natural unit of this cryptosystem: one block per encoded nibble-gram. `__iter__`
        flattens it to individual ints for compatibility.
        """
        yield from self.get_header()
        readers = [BufferedNibbleGramReader(stream) for stream in self.to_encrypt]
        for length, key in self.consume_grams(readers, "Encrypting"):
            yield self.encode_block(key, length)

    def chunks(self, chunk_size: int = CHUNK_SIZE) -> Iterator[bytes]:
        """Yields the ciphertext in chunks of roughly `chunk_size` bytes.

        Lets a caller write the ciphertext out as it is produced, instead of holding all of it in
        memory. `bytes(encrypter)` still works and is fine for small inputs.
        """
        buffer = bytearray()
        for block in self.blocks():
            buffer += block
            if len(buffer) >= chunk_size:
                yield bytes(buffer)
                buffer.clear()
        if buffer:
            yield bytes(buffer)

    def __iter__(self) -> Generator[int, None, None]:
        yield from itertools.chain.from_iterable(self.blocks())


class LengthChecksumEncrypter(Encrypter):
    def get_encryption_version(self) -> int:
        return 2

    def is_incomplete(self, buffers: Sequence["BufferedNibbleGramReader"]) -> bool:
        return any(not b.eof() for b in buffers)

    def total_nibbles(self) -> int:
        return max(self.buffer_lengths) * 2

    def pad_nibble_gram(self, buffer_index: int, length: int) -> bytes | None:  # noqa: ARG002
        """Pads every exhausted plaintext with random nibbles, regardless of which one it is.

        Safe because the length header lets decryption truncate, and random padding is better for
        deniability than zeros. Only reached for readers genuinely at end of stream -- padding one
        that still held data is what corrupted plaintexts.
        """
        # One bulk draw rather than `length` separate calls, each masked to a nibble.
        return bytes(byte & 0x0F for byte in self.rng.randbytes(length))

    def get_header(self) -> Iterator[bytes]:
        block_header = (
            0b10000000 | self.get_encryption_version()
        )  # the magic length checksum bit and filetype version number
        yield bytes([block_header])
        lengths = tuple(
            BytesIO(struct.pack("<Q", get_length(stream))) for stream in self.to_encrypt
        )
        try:
            yield from Encrypter(
                self.substitution_alphabet, lengths, status_callback=None, rng=self.rng
            ).blocks()
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


def encode(n: int) -> bytes:
    orig_n = n
    ret = bytearray([n & 0b11111111])
    for test, mask in encoding_steps:
        if n <= test:
            ret[0] = ret[0] | mask
            return bytes(ret)
        n >>= 8
        ret = bytearray([n & 0b11111111]) + ret
    message = (
        f"Integer {orig_n} is too big to encode; the largest supported value is {MAX_ENCODE_VALUE}"
    )
    raise EncodingError(message)


def decode(byte_array: bytes | bytearray | IO) -> int | None:
    to_close = None
    if isinstance(byte_array, (bytes, bytearray)):
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
        for _ in range(num_trailing_bytes):
            n <<= 8
            raw_byte = byte_array.read(1)
            if len(raw_byte) < 1:
                message = "Unexpected end of stream while decoding a variable-width integer"
                raise MalformedCiphertextError(message)
            byte = raw_byte[0]
            n |= byte
        return n
    finally:
        if to_close is not None:
            to_close.close()


# An encrypter for version 3 of the file spec.
class DictionaryEncrypter(LengthChecksumEncrypter):
    def __init__(
        self,
        substitution_alphabet: CommonNibbleGramsTypeHint,
        to_encrypt: Sequence[BinaryIO],
        status_callback: StatusCallbackTypeHint = None,
        rng: random.Random | None = None,
    ) -> None:
        super().__init__(substitution_alphabet, to_encrypt, status_callback, rng)
        self.dictionary: dict[bytes, int] = {}
        self.dictionary_items: list[bytes] = []
        # `can_encode` consults the substitution alphabet while building and the dictionary
        # afterwards; an explicit flag rather than testing the dictionary for emptiness.
        self._dictionary_built = False
        self.build_dictionary()
        self._dictionary_built = True

    def get_encryption_version(self) -> int:
        return 3

    def build_dictionary(self) -> None:
        """Counts which nibble-gram tuples the plaintexts use, most frequent first.

        Driven by the shared walk, which supplies the length-1 fallback this pass lacked: with its
        own loop, a gram the secrets could not encode consumed nothing and the walk spun forever --
        exactly the `-f/--force-encrypt` case.
        """
        readers = [BufferedNibbleGramReader(stream) for stream in self.to_encrypt]
        hits: dict[bytes, int] = {}
        for _length, key in self.consume_grams(readers, "Building Dictionary"):
            hits[key] = hits.get(key, 0) + 1
        # Every single-nibble gram the secrets can encode needs an entry, so encryption can always
        # fall back to length 1. Weight 0 keeps observed grams ahead of these fillers.
        #
        # Only grams actually in the substitution alphabet are added. Adding all 16**n
        # unconditionally meant `get_header` later looked up a gram the alphabet lacked; because the
        # alphabet is a defaultdict, that silently inserted an empty array and then raised
        # IndexError on [0]. Iterated lazily rather than materialised as a set: 16**n is 16.7M
        # tuples for 6 secrets.
        encodable_single_grams = self.substitution_alphabet.get(1, {})
        for combination in itertools.product(range(16), repeat=len(self.to_encrypt)):
            key = bytes(combination)
            if key not in hits and key in encodable_single_grams:
                hits[key] = 0
        # Sorted over the mapping rather than a set difference: iteration order of a set of tuples
        # of `bytes` varies with PYTHONHASHSEED, so dictionary indices differed between runs and
        # defeated `--seed` reproducibility. The gram itself breaks ties deterministically.
        self.dictionary_items = sorted(hits, key=lambda gram: (-hits[gram], gram))
        self.dictionary = {gram: index for index, gram in enumerate(self.dictionary_items)}
        # reset the files back to their first bytes
        for e in self.to_encrypt:
            e.seek(0)

    def can_encode(self, key: bytes, length: int) -> bool:
        # While encrypting, the dictionary is the authority; while building it, the base class's
        # substitution-alphabet check is used instead.
        if self._dictionary_built:
            return key in self.dictionary
        return super().can_encode(key, length)

    def encode_block(self, key: bytes, length: int) -> bytes:  # noqa: ARG002
        # `length` is part of the hook's contract; a dictionary index already implies it.
        return encode(self.dictionary[key])

    def get_header(self) -> Iterator[bytes]:
        yield from super().get_header()
        # The dictionary itself: one (certificate offset, gram length) pair per entry.
        yield encode(len(self.dictionary))
        for grams in self.dictionary_items:
            gram_length = unpack_gram_length(grams, len(self.to_encrypt))
            # An explicit check rather than `assert`, which vanishes under -O. build_dictionary only
            # admits grams the alphabet can encode, so reaching this is a bug, not bad input.
            offsets = self.substitution_alphabet.get(gram_length, {}).get(grams)
            if gram_length > 255 or not offsets:
                message = (
                    f"Cannot write a dictionary entry for {grams!r}: the substitution alphabet has "
                    f"no offset for it at length {gram_length}. Please report this as a bug."
                )
                raise LenticryptError(message)
            yield encode(offsets[0])
            yield bytes([gram_length])


index_type_map = FrozenDict({1: "B", 2: "H", 4: "L", 8: "Q"})

# Byte lengths the block header can encode an offset in.
VALID_INDEX_BYTES = frozenset(index_type_map)


class _NibbleAssembler:
    """Reassembles a plaintext from nibbles, honoring the declared length.

    A single place that owns the half-byte carry and the `file_length` bound. There were four
    near-identical copies of this carry logic, and the one in `_decrypt_dictionary` checked the
    length bound only between blocks -- so a final multi-nibble block could overshoot, and an empty
    plaintext still produced one byte.
    """

    def __init__(self, file_length: int | None = None) -> None:
        self.file_length = file_length
        self.num_bytes = 0
        self._pending: int | None = None

    @property
    def complete(self) -> bool:
        return self.file_length is not None and self.num_bytes >= self.file_length

    def push(self, nibbles: Sequence[int]) -> Iterator[int]:
        """Emits whole bytes assembled from `nibbles`, stopping at the declared length."""
        for nibble in nibbles:
            if self.complete:
                return
            if self._pending is None:
                self._pending = nibble << 4
            else:
                yield self._pending | nibble
                self._pending = None
                self.num_bytes += 1

    def flush(self) -> Iterator[int]:
        """Emits a trailing half byte, if the plaintext length calls for one."""
        if self._pending is not None and not self.complete:
            yield self._pending
            self.num_bytes += 1
            self._pending = None


def _load_certificate(certificate: IOWrappable) -> bytearray:
    """Expands a certificate into one nibble per element.

    Reads in blocks rather than a byte at a time, which for a multi-megabyte certificate was
    O(n) Python iterations to do what two C-level calls can.
    """
    nibbles = bytearray()
    with IOWrapper(certificate) as stream:
        while True:
            block = stream.read(READ_BLOCK_BYTES)
            if not block:
                break
            for byte in block:
                nibbles.append((byte & 0b11110000) >> 4)
                nibbles.append(byte & 0b00001111)
    return nibbles


def _certificate_nibbles(cert: Sequence[int], index: int, length: int) -> Sequence[int]:
    """The `length` nibbles at `index`, or zeros if the ciphertext points outside the certificate.

    Also covers the truncated-slice case: `cert[index:index + length]` silently returns fewer
    elements near the end, which `_decrypt_dictionary` then indexed past the end of.
    """
    if index < 0 or index >= len(cert):
        logger.warning(
            f"Decrypted invalid certificate index {index} "
            f"(maximum value is {len(cert) - 1}); substituting zeros"
        )
        return bytes(length)
    nibbles = cert[index : index + length]
    if len(nibbles) < length:
        logger.warning(
            f"Certificate index {index} has only {len(nibbles)} of {length} nibbles; padding"
        )
        return bytes(nibbles) + bytes(length - len(nibbles))
    return nibbles


def _read_exactly(stream: IO, count: int, what: str) -> bytes:
    """Reads exactly `count` bytes or raises, so truncation cannot surface as a struct.error."""
    data = stream.read(count)
    if len(data) < count:
        message = f"Unexpected end of ciphertext while reading {what}"
        raise MalformedCiphertextError(message)
    return data


def _read_dictionary(stream: IO) -> list[tuple[int, int]]:
    """Reads the v3 dictionary header: one (certificate offset, gram length) pair per entry."""
    dictionary_length = decode(stream)
    if dictionary_length is None:
        message = "Unexpected end of ciphertext while reading the dictionary size"
        raise MalformedCiphertextError(message)
    dictionary = []
    for _entry in range(dictionary_length):
        index = decode(stream)
        if index is None:
            message = "Unexpected end of ciphertext while reading a dictionary entry"
            raise MalformedCiphertextError(message)
        dictionary.append((index, _read_exactly(stream, 1, "a dictionary entry length")[0]))
    return dictionary


def _decrypt_dictionary(
    stream: IO, assembler: "_NibbleAssembler", cert: Sequence[int]
) -> Iterator[int]:
    """Decrypts a version 3 body, whose blocks are indices into a dictionary in the header."""
    dictionary = _read_dictionary(stream)
    while not assembler.complete:
        dict_index = decode(stream)
        if dict_index is None:
            message = "Unexpected end of ciphertext before the plaintext was complete"
            raise MalformedCiphertextError(message)
        if dict_index >= len(dictionary):
            message = (
                f"Invalid dictionary index {dict_index}; "
                f"the maximum valid index is {len(dictionary) - 1}"
            )
            raise MalformedCiphertextError(message)
        index, length = dictionary[dict_index]
        yield from assembler.push(_certificate_nibbles(cert, index, length))
    yield from assembler.flush()


def _read_block_header(header: int) -> tuple[int, int]:
    """Splits an indexed-gram block header into `(gram length, index width in bytes)`."""
    index_bytes = (header & 0b00000111) + 1
    if index_bytes not in VALID_INDEX_BYTES:
        message = f"Invalid block header: index byte length of {index_bytes} is not valid"
        raise MalformedCiphertextError(message)
    return ((header >> 3) & 0b00001111) + 1, index_bytes


def _decrypt_blocks(
    stream: IO, cert: Sequence[int], assembler: "_NibbleAssembler"
) -> Iterator[int]:
    """Decrypts indexed-gram blocks, and dispatches to the dictionary body on a length header."""
    while not assembler.complete:
        header = stream.read(1)
        if not header:
            break
        if header[0] & 0b10000000:
            version = header[0] & 0b01111111
            logger.info(f"Found length header. File format version is {version}")
            if version > ENCRYPTION_VERSION:
                message = (
                    f"This ciphertext declares file format version {version}, but this build "
                    f"understands at most version {ENCRYPTION_VERSION}"
                )
                raise UnsupportedVersionError(message)
            # The next 8 encrypted bytes are the plaintext length, encoded as blocks themselves.
            raw_length = bytes(_decrypt_blocks(stream, cert, _NibbleAssembler(file_length=8)))
            if len(raw_length) < 8:
                message = "Unexpected end of ciphertext while reading the plaintext length"
                raise MalformedCiphertextError(message)
            assembler.file_length = struct.unpack("<Q", raw_length)[0]
            logger.info(f"Plaintext file length is {assembler.file_length} bytes")
            if version == 3:
                yield from _decrypt_dictionary(stream, assembler, cert)
                return
            continue
        length, index_bytes = _read_block_header(header[0])
        index = stream.read(index_bytes)
        if len(index) < index_bytes:
            break
        offset = struct.unpack("<" + index_type_map[index_bytes], index)[0]
        yield from assembler.push(_certificate_nibbles(cert, offset, length))
    yield from assembler.flush()
    if assembler.file_length is not None and not assembler.complete:
        # The ciphertext declared a length it did not deliver. Returning the short plaintext
        # silently would hand back a truncated file as though it were the whole thing.
        message = (
            f"Ciphertext ended after {assembler.num_bytes} bytes, but declares a plaintext of "
            f"{assembler.file_length} bytes"
        )
        raise MalformedCiphertextError(message)


def decrypt_chunks(
    ciphertext: IOWrappable,
    certificate: IOWrappable | None = None,
    *,
    cert: Sequence[int] | None = None,
    chunk_size: int = CHUNK_SIZE,
) -> Iterator[bytes]:
    """Decrypts `ciphertext`, yielding the plaintext in chunks of roughly `chunk_size` bytes.

    Lets a caller write the plaintext out as it is recovered, rather than building the whole thing
    in memory first.
    """
    buffer = bytearray()
    for byte in decrypt(ciphertext, certificate, cert=cert):
        buffer.append(byte)
        if len(buffer) >= chunk_size:
            yield bytes(buffer)
            buffer.clear()
    if buffer:
        yield bytes(buffer)


def decrypt(
    ciphertext: IOWrappable,
    certificate: IOWrappable | None = None,
    *,
    cert: Sequence[int] | None = None,
) -> Generator[int, None, None]:
    """Decrypts `ciphertext` with `certificate`, yielding the plaintext one byte at a time.

    Args:
        ciphertext: The ciphertext, as a path, stream, bytes, or iterable of ints.
        certificate: The secret to decrypt with. Ignored if `cert` is given.
        cert: A pre-expanded certificate, one nibble per element, to avoid re-expanding it across
            repeated calls.

    Yields:
        Successive plaintext bytes.

    Raises:
        MalformedCiphertextError: The ciphertext is truncated or internally inconsistent.
        UnsupportedVersionError: The ciphertext declares a file format this build cannot read.
    """
    if cert is None:
        if certificate is None:
            message = "decrypt() needs either a certificate or a pre-expanded cert"
            raise LenticryptError(message)
        cert = _load_certificate(certificate)
    with IOWrapper(ciphertext) as stream:
        try:
            yield from _decrypt_blocks(stream, cert, _NibbleAssembler())
        except (EOFError, gzip.BadGzipFile, zlib.error) as error:
            # A damaged compression envelope is still a damaged ciphertext, and should read as one
            # rather than as an `EOFError` traceback from deep inside gzip. Caught narrowly on
            # purpose: a generic OSError here could be a real disk failure, which must not be
            # relabeled as malformed input.
            message = f"The ciphertext is not readable: {error}"
            raise MalformedCiphertextError(message) from error
