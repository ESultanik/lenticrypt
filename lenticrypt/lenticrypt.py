import array
import collections.abc
import gzip
import itertools
import random
import struct
import sys

from io import BytesIO
from typing import Any, BinaryIO, Callable, Dict, IO, Iterable, Iterator, MutableSequence, Optional, Sequence, Tuple, Union

ENCRYPTION_VERSION = 3

StatusCallbackTypeHint = Optional[Callable[[int, int, str], Any]]


def is_power2(num):
    """tests if a number is a power of two"""
    return num != 0 and ((num & (num - 1)) == 0)


NibbleGramTypeHint = Tuple[int, ...]


def read_nibble_gram(byte_array: Sequence[int], index: int, length: int) -> NibbleGramTypeHint:
    if not is_power2(length):
        raise ValueError(f'length must be a power of two; received {length}')
    offset = index // 2
    if length == 1:
        # we are reading a single nibble, which is an edge case since in all other cases we are reading whole bytes
        if index % 2 == 0:
            return ((byte_array[offset] & 0b11110000) >> 4,)
        else:
            return (byte_array[offset] & 0b00001111,)
    else:
        if index % 2 != 0:
            # we are ending on the first nibble of a byte
            b = array.array('B', [read_nibble_gram(byte_array, index, 1)[0]])
            offset += 1
            new_length = length - 2
        else:
            b = array.array('B')
            new_length = length
        for byte in byte_array[offset:offset+length//2]:
            b.append((byte & 0b11110000) >> 4)
            b.append(byte & 0b00001111)
        if index % 2 != 0:
            # we are ending on the first nibble of a byte
            b.append(read_nibble_gram(byte_array, index + length - 1, 1)[0])
        return tuple(b)


NibbleGramsTypeHint = Dict[Tuple[NibbleGramTypeHint, ...], MutableSequence[int]]
CommonNibbleGramsTypeHint = Dict[int, NibbleGramsTypeHint]


def find_common_nibble_grams(certificates,
                             nibble_gram_lengths=(1, 2, 4, 8, 16),
                             status_callback: StatusCallbackTypeHint = None) -> CommonNibbleGramsTypeHint:
    all_nibbles: CommonNibbleGramsTypeHint = {} # maps a nibble value to a common index
    for nibble_gram_length in nibble_gram_lengths:
        nibbles: NibbleGramsTypeHint = {}
        all_nibbles[nibble_gram_length] = nibbles
        range_max = min(len(c) for c in certificates)*2 - nibble_gram_length + 1
        for index in range(0, range_max):
            pair = tuple(read_nibble_gram(c, index, nibble_gram_length) for c in certificates)
            if pair in nibbles:
                nibbles[pair].append(index)
            else:
                nibbles[pair] = array.array('L', [index])
            if status_callback is not None:
                status_callback(index, range_max, "Building Index for %s-nibble-grams" % nibble_gram_length)
    return all_nibbles


class BufferedNibbleGramReader:
    def __init__(self, stream, max_nibble_gram_length = None):
        self.stream = stream
        self.max_nibble_gram_length = max_nibble_gram_length
        self._buffer = array.array('B')
        self.has_nibbles(1)

    def get_nibbles(self, length):
        r = self.peek_nibbles(length)
        if r is not None:
            del self._buffer[:length]
        return r

    def peek_nibbles(self, length):
        if not self.has_nibbles(length):
            return None
        else:
            return tuple(self._buffer[:length])

    def has_nibbles(self, length):
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


def get_length(stream: IO) -> int:
    """Gets the number of bytes in the stream."""
    old_position = stream.tell()
    stream.seek(0)
    length = 0
    while True:
        r = stream.read(1024)
        if not r:
            break
        length += len(r)
    stream.seek(old_position)
    return length


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

    def is_incomplete(self, buffers):
        return buffers[0]

    def get_max_length(self):
        if self.status_callback is None:
            return None
        else:
            return self.buffer_lengths[0]

    def process_nibble(self, n, buffer_index, length):
        if n is None and buffer_index > 0:
            return tuple([0]*length)
        else:
            return n

    def get_tuple(self, ng, length):
        if ng[0] is None or max(map(len,ng)) < length:
            return None
        else:
            return tuple(ng)

    def are_valid_nibbles(self, ng, length):
        return not (ng[0] is None or max(map(len,ng)) < length)

    def process_nibbles(self, ng, length, buffers):
        pair = tuple(ng)
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
            assert(length <= 16) # if we want to support longer lengths, we will have to allocate more bits in the header, pearhaps using the currently used one
            block_header = ((length - 1) << 3) | (index_bytes - 1)
            for byte in struct.pack("<B" + index_type, block_header, index):
                yield byte
        elif length == 1:
            sys.stderr.write("Warning: there is insufficient entropy in the input secrets to encode the byte pair " + str(pair) + "! The resulting ciphertext will not decrypt to the correct plaintext.\n")
            # consume these bytes
            for b in buffers:
                b.get_nibbles(length)

    def __iter__(self):
        for byte in self.get_header():
            yield byte
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
                ng = []
                for i, b in enumerate(buffers):
                    n = b.peek_nibbles(length)
                    ng.append(self.process_nibble(n, i, length))
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
        return sum(map(lambda b : not b.eof(), buffers))

    def get_max_length(self):
        if self.status_callback is None:
            return None
        else:
            return max(self.buffer_lengths)

    def are_valid_nibbles(self, ng, length):
        return max(map(len,ng)) >= length

    def process_nibble(self, n, buffer_index, length):
        if n is None:
            # if we are using a length checksum, we can make the padded bytes random:
            return tuple([random.randint(0, 15) for j in range(length)])
        else:
            return n

    def get_header(self):
        block_header = 0b10000000 | self.get_encryption_version() # the magic length checksum bit and filetype version number
        yield block_header
        lengths = tuple(BytesIO(struct.pack("<Q", get_length(l))) for l in self.to_encrypt)
        for b in Encrypter(self.substitution_alphabet, lengths, status_callback=None):
            yield b


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
    raise Exception("Integer %s is too big to encode!  The biggest value supported is %s." % (orig_n, MAX_ENCODE_VALUE))


def decode(byte_array: Union[bytes, bytearray, BinaryIO]) -> Optional[int]:
    if isinstance(byte_array, bytes) or isinstance(byte_array, bytearray):
        byte_array = BytesIO(byte_array)
    num_trailing_bytes = 0
    byte = byte_array.read(1)
    if len(byte) < 1:
        return None
    byte = byte[0]
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
        byte = byte_array.read(1)
        if len(byte) < 1:
            raise Exception("Error: expected another byte in the stream!")
        byte = byte[0]
        n |= byte
    return n


# An encrypter for version 3 of the file spec.
class DictionaryEncrypter(LengthChecksumEncrypter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dictionary = {}
        self.dictionary_items = []
        self.build_dictionary()

    def get_encryption_version(self):
        return 3

    def build_dictionary(self):
        max_length = self.get_max_length()
        if self.status_callback is not None:
            max_length *= len(self.sorted_lengths) * 2
        count = 0
        buffers = [BufferedNibbleGramReader(e, self.sorted_lengths[0]) for e in self.to_encrypt]
        dictionary_hits = {}
        while self.is_incomplete(buffers):
            # if the files are not the same length, encrypt to the length of to_encrypt1
            for length_num, length in enumerate(self.sorted_lengths):
                if self.status_callback is not None:
                    count += 1
                    self.status_callback(count, max_length, "Building Dictionary")
                ng = []
                for i, b in enumerate(buffers):
                    n = b.peek_nibbles(length)
                    ng.append(self.process_nibble(n, i, length))
                if not self.are_valid_nibbles(ng, length):
                    continue
                pair = tuple(ng)
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
        missing_grams = set(itertools.product(*[map(lambda j : (j,), range(16)) for i in range(len(self.to_encrypt))]))
        for item in self.dictionary_items:
            missing_grams.discard(item)
        for missing in missing_grams:
            self.dictionary_items.append(missing)
            dictionary_hits[missing] = 1
        self.dictionary_items = sorted(self.dictionary_items, key=lambda p: dictionary_hits[p], reverse=True)
        self.dictionary = {v: idx for idx, v in enumerate(self.dictionary_items)}
        # reset the files back to their first bytes
        for e in self.to_encrypt:
            e.seek(0)

    def process_nibbles(self, ng, length, buffers):
        pair = tuple(ng)
        if pair in self.dictionary:
            # consume the nibbles!
            for b in buffers:
                b.get_nibbles(length)
            for byte in encode(self.dictionary[pair]):
                yield byte
        elif length == 1:
            sys.stderr.write("Warning: there is insufficient entropy in the input secrets to encode the byte pair " + str(pair) + "! The resulting ciphertext will not decrypt to the correct plaintext.\n")
            # consume these bytes
            for b in buffers:
                b.get_nibbles(length)

    def get_header(self):
        for byte in super(DictionaryEncrypter, self).get_header():
            yield byte
        # add the dictionary:
        for byte in encode(len(self.dictionary)):
            yield byte
        for pair in self.dictionary_items:
            index = self.substitution_alphabet[len(pair[0])][pair][0]
            for byte in encode(index):
                yield byte
            lp = len(pair[0])
            assert lp <= 255
            yield lp


# block header, 8 bits:
# MSB -> X X X X X X X X <- LSB
#                 |-----| <-- index_bytes - 1 (since index_bytes is always greater than zero)
#         |-------| <-- length - 1 (since length is always greater than zero)
#       |-| <-- If 1, then the following 7 bits are a filetype version number and the following blocks are the encrypted 8 bytes encoding the length of the file
# def encrypt(
#         substitution_alphabet: CommonNibbleGramsTypeHint,
#         to_encrypt: Union[Sequence[int], Sequence[BinaryIO]],
#         add_length_checksum: bool = False,
#         status_callback: StatusCallbackTypeHint = None):
#     if add_length_checksum:
#         block_header = 0b10000000 | ENCRYPTION_VERSION # the magic length checksum bit and filetype version number
#         yield block_header
#         lengths = tuple(get_length(BytesIO(struct.pack("<Q", l))) for l in to_encrypt)
#         yield from encrypt(substitution_alphabet, lengths, add_length_checksum=False, status_callback=None)
#     sorted_lengths = sorted(substitution_alphabet.keys(), reverse=True)
#     buffer_lengths = None
#     if status_callback is not None:
#         buffer_lengths = tuple(get_length(b) for b in to_encrypt)
#     buffers = [BufferedNibbleGramReader(e, sorted_lengths[0]) for e in to_encrypt]
#     max_length = None
#     if add_length_checksum:
#         completion_test = lambda: sum(map(lambda b : not b.eof(), buffers))
#         if status_callback is not None:
#             max_length = max(buffer_lengths)
#     else:
#         completion_test = lambda: buffers[0]
#         if status_callback is not None:
#             max_length = buffer_lengths[0]
#     if status_callback is not None:
#         max_length *= len(sorted_lengths) * 2
#     count = 0
#     while completion_test():
#         # if the files are not the same length, encrypt to the length of to_encrypt1
#         for length_num, length in enumerate(sorted_lengths):
#             if status_callback is not None:
#                 count += 1
#                 status_callback(count, max_length, "Encrypting")
#             ng = []
#             for i, b in enumerate(buffers):
#                 n = b.peek_nibbles(length)
#                 if n is None and (i > 0 or add_length_checksum):
#                     # this will happen if this plaintext is shorter than the first plaintext; just pad its tail with zeros
#                     if add_length_checksum:
#                         # but if we are using a length checksum, we can make the padded bytes random:
#                         n = tuple([random.randint(0, 15) for j in range(length)])
#                     else:
#                         n = tuple([0]*length)
#                 ng.append(n)
#             if (ng[0] is None and not add_length_checksum) or max(map(len,ng)) < length:
#                 continue
#             pair = tuple(ng)
#             if pair in substitution_alphabet[length]:
#                 # consume the nibbles!
#                 for b in buffers:
#                     b.get_nibbles(length)
#                 index = random.choice(substitution_alphabet[length][pair])
#                 index_bytes = 8
#                 index_type = "Q" # unsigned long long
#                 if index < 256:
#                     index_bytes = 1
#                     index_type = "B" # unsigned char
#                 elif index < 65536:
#                     index_bytes = 2
#                     index_type = "H" # unsigned short
#                 elif index < 4294967296:
#                     index_bytes = 4
#                     index_type = "L" # unsigned long
#                 assert(length <= 16) # if we want to support longer lengths, we will have to allocate more bits in the header, pearhaps using the currently used one
#                 block_header = ((length - 1) << 3) | (index_bytes - 1)
#                 for byte in struct.pack("<B" + index_type, block_header, index):
#                     yield byte
#                 if status_callback is not None:
#                     count += len(sorted_lengths) - (length_num + 1)
#                 break
#             elif length == 1:
#                 sys.stderr.write("Warning: there is insufficient entropy in the input secrets to encode the byte pair " + str(pair) + "! The resulting ciphertext will not decrypt to the correct plaintext.\n")
#                 # consume these bytes
#                 for b in buffers:
#                     b.get_nibbles(length)


index_type_map = {
    1 : 'B',
    2 : 'H',
    4 : 'L',
    8 : 'Q'}


class IOWrapper(object):
    def __init__(self, wrapped: Union[str, BinaryIO]):
        self.wrapped = wrapped
        self._file = None

    def new_instance(self):
        if self.wrapped == '-':
            return sys.stdin
        elif isinstance(self.wrapped, collections.abc.Iterable):
            if not isinstance(self.wrapped, bytes) and not isinstance(self.wrapped, bytearray):
                return BytesIO(bytes([b for b in self.wrapped]))
            else:
                return BytesIO(self.wrapped)
        else:
            return open(self.wrapped)

    def __enter__(self):
        if isinstance(self.wrapped, BytesIO) or isinstance(self.wrapped, gzip.GzipFile):
            return self.wrapped
        else:
            self._file = self.new_instance()
            return self._file.__enter__()

    def __exit__(self, type, value, tb):
        if self._file is not None:
            self._file.__exit__(type, value, tb)
            self._file = None


class GzipIOWrapper(IOWrapper):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def new_instance(self):
        return gzip.GzipFile(fileobj=super().new_instance())


def _decrypt_dictionary(stream, file_length, cert):
    # read the dictionary index:
    dictionary_length = decode(stream)
    dictionary = []
    for i in range(dictionary_length):
        index = decode(stream)
        b = stream.read(1)
        if len(b) < 1:
            raise Exception("Unexpected end of file while decodeing dictionary!")
        length = b[0]
        dictionary.append((index, length))
    last_nibble = None
    num_bytes = 0
    while num_bytes < file_length:
        dict_index = decode(stream)
        if dict_index >= len(dictionary):
            raise Exception("Invalid dictionary index %s!  Maximum valid index is %s." % (dict_index, len(dictionary)-1))
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


def decrypt(ciphertext: Iterable[int], certificate, cert=None, file_length=None) -> Iterator[int]:
    # the file format is specified in a comment at the top of the encrypt(...) function above.
    if cert is None:
        cert = []
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
                sys.stderr.write("Found length header. File format version is " + str(version) + "\n")
                if version > ENCRYPTION_VERSION:
                    sys.stderr.write("Warning: This ciphertext appears to have been encrypted with a newer version of the cryptosystem (version " + str(version / 10.0) + ").\n")                    
                # the next 8 encrypted bytes encode the length of the plaintext
                raw_length = bytearray(decrypt(stream, None, cert=cert, file_length=8))
                file_length = struct.unpack("<Q", raw_length)[0]
                sys.stderr.write("Plaintext file length is " + str(file_length) + " bytes\n")
                if version == 3:
                    for byte in _decrypt_dictionary(stream, file_length, cert):
                        yield byte
                    return
                continue
            index_bytes = (header & 0b00000111) + 1
            if index_bytes not in index_type_map:
                raise Exception("Invalid block header: Received an invalid index byte length of " + str(index_bytes) + " bytes!")
            length = ((header >> 3) & 0b00001111) + 1
            index = stream.read(index_bytes)
            if not index:
                break
            n = struct.unpack("<" + index_type_map[index_bytes], index)[0]
            if n >= len(cert):
                sys.stderr.write("Warning: Decrypted invalid certificate index %s (maximum value is %s)\n" % (n, len(cert)-1))
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
