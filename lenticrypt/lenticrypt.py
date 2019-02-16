import array
import itertools
import logging
import random
import struct

from collections import defaultdict
from io import BytesIO
from typing import Any, BinaryIO, Callable, Dict, Generator, List, Optional, Sequence, Tuple, Union

from .iowrapper import get_length, IOWrappable, IOWrapper
from .utils import FrozenDict

logger = logging.getLogger(name='lenticrypt')

ENCRYPTION_VERSION: int = 3
MAJOR_VERSION: int = 0
MINOR_VERSION: int = 1
VERSION: str = f"{MAJOR_VERSION}.{ENCRYPTION_VERSION}.{MINOR_VERSION}"

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
        raise ValueError(f'length must be a power of two; received {length}')

    return (bytes(ng) for ng in zip(*(itertools.islice(nibbles, i, None) for i, nibbles in enumerate(itertools.tee(read_nibbles(byte_array), length)))))


NibbleGramsTypeHint = Dict[Tuple[bytes, ...], array.array]
CommonNibbleGramsTypeHint = Dict[int, NibbleGramsTypeHint]


def find_common_nibble_grams(certificates: Sequence[Sequence[int]],
                             nibble_gram_lengths=(1, 2, 4, 8, 16),
                             status_callback: StatusCallbackTypeHint = None,
                             stop_when_sufficient: bool = False) -> CommonNibbleGramsTypeHint:
    all_nibbles: CommonNibbleGramsTypeHint = {} # maps a nibble value to a common index
    min_cert_length = min(len(c) for c in certificates)
    for nibble_gram_length in nibble_gram_lengths:
        nibbles: NibbleGramsTypeHint = defaultdict(lambda: array.array('L'))
        all_nibbles[nibble_gram_length] = nibbles
        range_max = min_cert_length * 2 - nibble_gram_length + 1
        for index, pair in enumerate(zip(*(read_nibble_grams(c, nibble_gram_length) for c in certificates))):
            nibbles[pair].append(index)
            if stop_when_sufficient and len(nibbles) >= (16*nibble_gram_length) ** len(certificates):
                return all_nibbles
            if status_callback is not None:
                status_callback(index, range_max, "Building Index for %s-nibble-grams" % nibble_gram_length)
    return all_nibbles


class BufferedNibbleGramReader:
    def __init__(self, stream: BinaryIO, max_nibble_gram_length: int = None):
        self.stream = stream
        self.max_nibble_gram_length = max_nibble_gram_length
        self._buffer: Optional[bytearray] = bytearray()
        self.has_nibbles(1)

    def get_nibbles(self, length: int) -> Optional[bytes]:
        r = self.peek_nibbles(length)
        if r is not None and self._buffer is not None:
            del self._buffer[:length]
        return r

    def peek_nibbles(self, length: int) -> Optional[bytes]:
        if self._buffer is None or not self.has_nibbles(length):
            return None
        else:
            return bytes(self._buffer[:length])

    def has_nibbles(self, length: int) -> bool:
        if self._buffer is None:
            return False
        elif len(self._buffer) >= length:
            return True
        b = self.stream.read((length - len(self._buffer) + 1)//2)
        if not b:
            if len(self._buffer) == 0:
                # we are done
                self._buffer = None
            return False
        else:
            for byte in b:
                self._buffer.append((byte & 0b11110000) >> 4)
                self._buffer.append(byte & 0b00001111)
            return True

    def eof(self):
        return self._buffer is None

    def __bool__(self):
        return not self.eof()

    __nonzero__ = __bool__


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
            status_callback: StatusCallbackTypeHint = None):
        self.substitution_alphabet = substitution_alphabet
        self.to_encrypt = to_encrypt
        self.sorted_lengths = sorted(substitution_alphabet.keys(), reverse=True)
        self.buffer_lengths = None
        self.status_callback = status_callback
        if self.status_callback is not None:
            self.buffer_lengths = [get_length(b) for b in self.to_encrypt]

    def get_header(self):
        return iter([])

    def is_incomplete(self, buffers) -> bool:
        return bool(buffers[0])

    def get_max_length(self):
        if self.status_callback is None:
            return None
        else:
            return self.buffer_lengths[0]

    def process_nibble(self, n: Optional[bytes], buffer_index: int, length: int) -> Optional[bytes]:
        if n is None and buffer_index > 0:
            return b'\0'*length
        else:
            return n

    def get_tuple(self, ng: Tuple[Optional[bytes], ...], length) -> Optional[Tuple[Optional[bytes], ...]]:
        if None in ng or max(len(n) for n in ng) < length:
            return None
        else:
            return ng

    def are_valid_nibbles(self, ng: Tuple[Optional[bytes], ...], length):
        return not (None in ng or max(len(n) for n in ng) < length)

    def process_nibbles(self, pair: Tuple[bytes, ...], length: int, buffers) -> Generator[int, None, None]:
        if length > 16:
            # if we want to support longer lengths, we will have to allocate more bits in the header, pearhaps using the currently used one
            raise Exception("Lenticrypt's encoding currently only supports nibble gram lengths up to 16")
        if pair in self.substitution_alphabet[length]:
            # consume the nibbles!
            for b in buffers:
                b.get_nibbles(length)
            index = random.choice(self.substitution_alphabet[length][pair])
            index_bytes = 8
            index_type = "Q" # unsigned long long
            if index < 256:
                index_bytes = 1
                index_type = "B" # unsigned char
            elif index < 65536:
                index_bytes = 2
                index_type = "H" # unsigned short
            elif index < 4294967296:
                index_bytes = 4
                index_type = "L" # unsigned long
            block_header = ((length - 1) << 3) | (index_bytes - 1)
            yield from iter(struct.pack("<B" + index_type, block_header, index))
        elif length == 1:
            logger.warning(f"There is insufficient entropy in the input secrets to encode the byte pair {pair!r}! The resulting ciphertext will not decrypt to the correct plaintext.")
            # consume these bytes
            for b in buffers:
                b.get_nibbles(length)

    def __iter__(self):
        yield from self.get_header()
        max_length = self.get_max_length()
        if self.status_callback is not None:
            max_length *= len(self.sorted_lengths) * 2
        count = 0
        buffers = [BufferedNibbleGramReader(e, self.sorted_lengths[0]) for e in self.to_encrypt]
        while self.is_incomplete(buffers):
            # if the files are not the same length, encrypt to the length of to_encrypt1
            for length_num, length in enumerate(self.sorted_lengths):
                if self.status_callback is not None:
                    count += 1
                    self.status_callback(count, max_length, "Encrypting")
                ng = tuple(self.process_nibble(b.peek_nibbles(length), i, length) for i, b in enumerate(buffers))
                if not self.are_valid_nibbles(ng, length):
                    continue
                success = False
                for byte in self.process_nibbles(ng, length, buffers):
                    success = True
                    yield byte
                    if self.status_callback is not None:
                        count += len(self.sorted_lengths) - (length_num + 1)
                if success:
                    break


class LengthChecksumEncrypter(Encrypter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_encryption_version(self):
        return 2

    def is_incomplete(self, buffers):
        return sum(1 for b in buffers if not b.eof())

    def get_max_length(self):
        if self.status_callback is None:
            return None
        else:
            return max(self.buffer_lengths)

    def are_valid_nibbles(self, ng, length):
        return max(len(n) for n in ng) >= length

    def process_nibble(self, n: Optional[bytes], buffer_index, length) -> Optional[bytes]:
        if n is None:
            # if we are using a length checksum, we can make the padded bytes random:
            return bytes([random.randint(0, 15) for _ in range(length)])
        else:
            return n

    def get_header(self):
        block_header = 0b10000000 | self.get_encryption_version() # the magic length checksum bit and filetype version number
        yield block_header
        lengths = tuple(BytesIO(struct.pack("<Q", get_length(l))) for l in self.to_encrypt)
        try:
            yield from iter(Encrypter(self.substitution_alphabet, lengths, status_callback=None))
        finally:
            for length in lengths:
                length.close()


encoding_steps = [(0b01111111, 0),
                  (0b00111111, 0b10000000),
                  (0b00011111, 0b11000000),
                  (0b00001111, 0b11100000),
                  (0b00000111, 0b11110000),
                  (0b00000011, 0b11111000),
                  (0b00000001, 0b11111100)]

MAX_ENCODE_VALUE = 2**(8*(len(encoding_steps)-1)) + (encoding_steps[-1][0] << (8*(len(encoding_steps)-1))) - 1


def encode(n: int) -> bytearray:
    orig_n = n
    ret = bytearray([n & 0b11111111])
    for test, mask in encoding_steps:
        if n <= test:
            ret[0] = ret[0] | mask
            return ret
        n >>= 8
        ret = bytearray([n & 0b11111111]) + ret
    raise Exception(f"Integer {orig_n} is too big to encode!  The biggest value supported is {MAX_ENCODE_VALUE}.")


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
        self.build_dictionary()

    def get_encryption_version(self):
        return 3

    def build_dictionary(self):
        max_length = self.get_max_length()
        if self.status_callback is not None:
            max_length *= len(self.sorted_lengths) * 2
        count = 0
        buffers = [BufferedNibbleGramReader(e, self.sorted_lengths[0]) for e in self.to_encrypt]
        dictionary_hits: Dict[Tuple[bytes, ...], int] = {}
        while self.is_incomplete(buffers):
            # if the files are not the same length, encrypt to the length of to_encrypt1
            for length_num, length in enumerate(self.sorted_lengths):
                if self.status_callback is not None:
                    count += 1
                    self.status_callback(count, max_length, "Building Dictionary")
                pair = tuple(self.process_nibble(b.peek_nibbles(length), i, length) for i, b in enumerate(buffers))
                if not self.are_valid_nibbles(pair, length):
                    continue
                if pair in self.substitution_alphabet[length]:
                    # consume the nibbles!
                    for b in buffers:
                        b.get_nibbles(length)
                    if pair not in dictionary_hits:
                        self.dictionary_items.append(pair)
                        dictionary_hits[pair] = 1
                    else:
                        dictionary_hits[pair] += 1
                    if self.status_callback is not None:
                        count += len(self.sorted_lengths) - (length_num + 1)
                    break
        # make sure that the dictionary contains all of the 1-nibble grams:
        missing_grams = set(itertools.product(*[[bytes([j]) for j in range(16)] for _ in range(len(self.to_encrypt))]))
        for missing in missing_grams - dictionary_hits.keys():
            self.dictionary_items.append(missing)
            dictionary_hits[missing] = 1
        self.dictionary_items = sorted(self.dictionary_items, key=lambda p: dictionary_hits[p], reverse=True)
        self.dictionary = {v: idx for idx, v in enumerate(self.dictionary_items)}
        # reset the files back to their first bytes
        for e in self.to_encrypt:
            e.seek(0)

    def process_nibbles(self, pair, length, buffers):
        if pair in self.dictionary:
            # consume the nibbles!
            for b in buffers:
                b.get_nibbles(length)
            yield from iter(encode(self.dictionary[pair]))
        elif length == 1:
            logger.warning(f"There is insufficient entropy in the input secrets to encode the byte pair {pair}! The resulting ciphertext will not decrypt to the correct plaintext.")
            # consume these bytes
            for b in buffers:
                b.get_nibbles(length)

    def get_header(self):
        yield from super().get_header()
        # add the dictionary:
        yield from iter(encode(len(self.dictionary)))
        for pair in self.dictionary_items:
            lp = len(pair[0])
            assert lp <= 255 and lp in self.substitution_alphabet
            index = self.substitution_alphabet[lp][pair][0]
            yield from iter(encode(index))
            yield lp


index_type_map = FrozenDict({
    1: 'B',
    2: 'H',
    4: 'L',
    8: 'Q'
})


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
            raise Exception(f"Invalid dictionary index {dict_index}!  Maximum valid index is {len(dictionary)-1}.")
        index, length = dictionary[dict_index]
        if length == 1:
            if last_nibble is None:
                last_nibble = cert[index] << 4
            else:
                yield last_nibble | cert[index]
                last_nibble = None
                num_bytes += 1
        else:
            nibbles = cert[index:index+length]
            if last_nibble is not None:
                yield last_nibble | nibbles[0]
                num_bytes += 1
                last_nibble = nibbles[-1] << 4
                nibbles = nibbles[1:-1]
            for index in range(0,len(nibbles),2):
                yield (nibbles[index] << 4) | nibbles[index+1]
                num_bytes += 1


def decrypt(ciphertext: IOWrappable,
            certificate: Optional[IOWrappable],
            cert: Optional[bytearray] = None,
            file_length: Optional[int] = None) -> Generator[int, None, None]:
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
                    logger.warning(f"This ciphertext appears to have been encrypted with a newer version of the cryptosystem (version {(version / 10.0)!s}).")
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
                raise Exception(f"Invalid block header: Received an invalid index byte length of {index_bytes!s} bytes!")
            length = ((header >> 3) & 0b00001111) + 1
            index = stream.read(index_bytes)
            if not index:
                break
            n = struct.unpack("<" + index_type_map[index_bytes], index)[0]
            if n >= len(cert):
                logger.warning(f"Decrypted invalid certificate index {n} (maximum value is {len(cert)-1})")
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
                nibbles = cert[n:n+length]
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
                        yield (nibbles[index] << 4) | nibbles[index+1]
                        num_bytes += 1
                        if file_length is not None and num_bytes >= file_length:
                            return
