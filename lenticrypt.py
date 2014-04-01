#!/usr/bin/env python2

import os, sys, itertools, random, struct, StringIO, gzip

ENCRYPTION_VERSION = 3

def get_terminal_size():
    env = os.environ
    def ioctl_GWINSZ(fd):
        try:
            import fcntl, termios, struct, os
            cr = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ,
        '1234'))
        except:
            return
        return cr
    cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
    if not cr:
        try:
            fd = os.open(os.ctermid(), os.O_RDONLY)
            cr = ioctl_GWINSZ(fd)
            os.close(fd)
        except:
            pass
    if not cr:
        cr = (env.get('LINES', 25), env.get('COLUMNS', 80))
    return int(cr[1]), int(cr[0])

class StatusLine(object):
    def __init__(self, stream = sys.stderr):
        self.stream = stream
        self.clear()
    def clear(self):
        width, height = get_terminal_size()
        self.stream.write("\r" + " "*width + "\r")
    def write(self, text):
        self.stream.write(text)

class ProgressBar(StatusLine):
    def __init__(self, stream = sys.stderr, max_value = 100):
        super(ProgressBar, self).__init__(stream)
        self.max_value = max_value
        self.value = 0
        self._last_percent = -1
    def update(self, value, status = ""):
        self.value = value
        percent = float(value) / float(self.max_value)
        if percent < 0:
            percent = 0
        elif percent > 1.0:
            percent = 1.0
        if int(percent * 100.0 + 0.5) != self._last_percent:
            self._last_percent = int(percent * 100.0 + 0.5)
            width, height = get_terminal_size()
            width -= 2
            pixels = int(float(width) * percent + 0.5)
            self.clear()
            self.write("[")
            if len(status) > 0:
                s = "%s %d%%" % (status, int(percent * 100.0 + 0.5))
            else:
                s = "%d%%" % int(percent * 100.0 + 0.5)
            status_start = (width - len(s)) / 2
            for i in range(width):
                if i == status_start:
                    for j in range(len(s)):
                        if s[j] == ' ' and j + i < pixels:
                            s = s[:j] + '=' + s[j+1:]
                    self.write(s)
                elif i > status_start and i < status_start + len(s):
                    pass
                elif i < pixels:
                    self.write("=")
                else:
                    self.write("-")
            self.write("]")

class ProgressBarCallback:
    def __init__(self):
        self.pb = None
    def __call__(self, value, max_value, status = ""):
        if self.pb is None:
            self.pb = ProgressBar(max_value = max_value)
        self.pb.update(value, status)
    def clear(self):
        if self.pb is not None:
            self.pb.clear()

def is_power2(num):
    """tests if a number is a power of two"""
    return num != 0 and ((num & (num - 1)) == 0)

def read_nibble_gram(byte_array, index, length):
    assert(is_power2(length))
    offset = index/2
    if length == 1:
        # we are reading a single nibble, which is an edge case since in all other cases we are reading whole bytes
        if index % 2 == 0:
            return ((byte_array[offset] & 0b11110000) >> 4,)
        else:
            return (byte_array[offset] & 0b00001111,)
    else:
        return tuple(byte_array[offset:offset+length/2])

def find_common_nibble_grams(certificates, nibble_gram_lengths = [1, 2, 4, 8, 16], status_callback=None):
    all_nibbles = {} # maps a nibble value to a common index
    for nibble_gram_length in nibble_gram_lengths:
        nibbles = {}
        all_nibbles[nibble_gram_length] = nibbles
        range_max = min(map(len, certificates))*2 - nibble_gram_length + 1
        for index in range(0,range_max):
            pair = tuple(map(lambda c : read_nibble_gram(c, index, nibble_gram_length), certificates))
            if pair in nibbles:
                nibbles[pair].append(index)
            else:
                nibbles[pair] = [index]
            if status_callback is not None:
                status_callback(index, range_max, "Building Index for %s-nibble-grams" % nibble_gram_length)
    return all_nibbles

class BufferedNibbleGramReader:
    def __init__(self, stream, max_nibble_gram_length):
        self.stream = stream
        self.max_nibble_gram_length = max_nibble_gram_length
        self._buffer = []
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
        b = self.stream.read(length - len(self._buffer))
        if not b:
            if len(self._buffer) == 0:
                # we are done
                self._buffer = None
            return False
        else:
            for byte in map(ord,b):
                self._buffer.append((byte & 0b11110000) >> 4)
                self._buffer.append(byte & 0b00001111)
            return True
    def eof(self):
        return self._buffer is None
    def __bool__(self):
        return not self.eof()
    __nonzero__=__bool__

def get_length(stream):
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
    def __init__(self, substitution_alphabet, to_encrypt, status_callback=None):
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
    def __init__(self, substitution_alphabet, to_encrypt, status_callback=None):
        super(LengthChecksumEncrypter, self).__init__(substitution_alphabet = substitution_alphabet, to_encrypt = to_encrypt, status_callback = status_callback)

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
        return not max(map(len,ng)) < length

    def process_nibble(self, n, buffer_index, length):
        if n is None:
            # if we are using a length checksum, we can make the padded bytes random:
            return tuple([random.randint(0, 15) for j in range(length)])
        else:
            return n

    def get_header(self):
        block_header = 0b10000000 | self.get_encryption_version() # the magic length checksum bit and filetype version number
        yield chr(block_header)
        lengths = map(lambda l : StringIO.StringIO(struct.pack("<Q", l)), map(get_length, self.to_encrypt))
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

def encode(n):
    orig_n = n
    ret = bytearray([n & 0b11111111])
    for test, mask in encoding_steps:
        if n <= test:
            ret[0] = ret[0] | mask
            return ret
        n >>= 8
        ret = bytearray([n & 0b11111111]) + ret
    raise Exception("Integer %s is too big to encode!  The biggest value supported is %s." % (orig_n, MAX_ENCODE_VALUE))

def decode(byte_array):
    if isinstance(byte_array, str) or isinstance(byte_array, bytearray):
        byte_array = StringIO.StringIO(byte_array)
    num_trailing_bytes = 0
    byte = byte_array.read(1)
    if not byte:
        return None
    byte = ord(byte)
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
    n = byte
    for i in range(num_trailing_bytes):
        n <<= 8
        byte = byte_array.read(1)
        if not byte:
            raise Exception("Error: expected another byte in the stream!")
        n |= ord(byte)
    return n

# An encrypter for version 3 of the file spec.
class DictionaryEncrypter(LengthChecksumEncrypter):
    def __init__(self, substitution_alphabet, to_encrypt, status_callback=None):
        super(DictionaryEncrypter, self).__init__(substitution_alphabet = substitution_alphabet, to_encrypt = to_encrypt, status_callback = status_callback)
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
        self.dictionary_items = sorted(self.dictionary_items, key=lambda pair : dictionary_hits[pair], reverse=True)
        self.dictionary = dict(map(reversed,enumerate(self.dictionary_items)))
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
                yield chr(byte)
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
            yield chr(byte)
        for pair in self.dictionary_items:
            index = self.substitution_alphabet[len(pair[0])][pair][0]
            for byte in encode(index):
                yield chr(byte)
            yield chr(len(pair[0]))

# block header, 8 bits:
# MSB -> X X X X X X X X <- LSB
#                 |-----| <-- index_bytes - 1 (since index_bytes is always greater than zero)
#         |-------| <-- length - 1 (since length is always greater than zero)
#       |-| <-- If 1, then the following 7 bits are a filetype version number and the following blocks are the encrypted 8 bytes encoding the length of the file
def encrypt(substitution_alphabet, to_encrypt, add_length_checksum=False, status_callback=None):
    if add_length_checksum:
        block_header = 0b10000000 | ENCRYPTION_VERSION # the magic length checksum bit and filetype version number
        yield chr(block_header)
        lengths = map(lambda l : StringIO.StringIO(struct.pack("<Q", l)), map(get_length, to_encrypt))
        for b in encrypt(substitution_alphabet, lengths, add_length_checksum=False, status_callback=None):
            yield b
    sorted_lengths = sorted(substitution_alphabet.keys(), reverse=True)
    buffer_lengths = None
    if status_callback is not None:
        buffer_lengths = [get_length(b) for b in to_encrypt]
    buffers = [BufferedNibbleGramReader(e, sorted_lengths[0]) for e in to_encrypt]
    max_length = None
    if add_length_checksum:
        completion_test = lambda : sum(map(lambda b : not b.eof(), buffers))
        if status_callback is not None:
            max_length = max(buffer_lengths)
    else:
        completion_test = lambda : buffers[0]
        if status_callback is not None:
            max_length = buffer_lengths[0]
    if status_callback is not None:
        max_length *= len(sorted_lengths) * 2
    count = 0
    while completion_test():
        # if the files are not the same length, encrypt to the length of to_encrypt1
        for length_num, length in enumerate(sorted_lengths):
            if status_callback is not None:
                count += 1
                status_callback(count, max_length, "Encrypting")
            ng = []
            for i, b in enumerate(buffers):
                n = b.peek_nibbles(length)
                if n is None and (i > 0 or add_length_checksum):
                    # this will happen if this plaintext is shorter than the first plaintext; just pad its tail with zeros
                    if add_length_checksum:
                        # but if we are using a length checksum, we can make the padded bytes random:
                        n = tuple([random.randint(0, 15) for j in range(length)])
                    else:
                        n = tuple([0]*length)
                ng.append(n)
            if (ng[0] is None and not add_length_checksum) or max(map(len,ng)) < length:
                continue
            pair = tuple(ng)
            if pair in substitution_alphabet[length]:
                # consume the nibbles!
                for b in buffers:
                    b.get_nibbles(length)
                index = random.choice(substitution_alphabet[length][pair])
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
                if status_callback is not None:
                    count += len(sorted_lengths) - (length_num + 1)
                break
            elif length == 1:
                sys.stderr.write("Warning: there is insufficient entropy in the input secrets to encode the byte pair " + str(pair) + "! The resulting ciphertext will not decrypt to the correct plaintext.\n")
                # consume these bytes
                for b in buffers:
                    b.get_nibbles(length)

index_type_map = {
    1 : 'B',
    2 : 'H',
    4 : 'L',
    8 : 'Q'}

class IOWrapper(object):
    def __init__(self, wrapped):
        self.wrapped = wrapped
        self._file = None
    def new_instance(self):
        return open(self.wrapped)
    def __enter__(self):
        if isinstance(self.wrapped, StringIO.StringIO) or isinstance(self.wrapped, gzip.GzipFile) or isinstance(self.wrapped, file):
            return self.wrapped
        else:
            self._file = self.new_instance()
            return self._file.__enter__()
    def __exit__(self, type, value, tb):
        if self._file is not None:
            self._file.__exit__(type, value, tb)

class GzipIOWrapper(IOWrapper):
    def __init__(self, wrapped):
        super(GzipIOWrapper, self).__init__(wrapped)
    def new_instance(self):
        return gzip.GzipFile(self.wrapped)

def _decrypt_dictionary(stream, file_length, cert):
    # read the dictionary index:
    dictionary_length = decode(stream)
    dictionary = []
    for i in range(dictionary_length):
        index = decode(stream)
        b = stream.read(1)
        if not b:
            raise Exception("Unexpected end of file while decodeing dictionary!")
        length = ord(b)
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
            for byte in cert[index:index+length]:
                yield byte
                num_bytes += 1

def decrypt(ciphertext, certificate, cert = None, file_length = None):
    # the file format is specified in a comment at the top of the encrypt(...) function above.
    if cert is None:
        cert = []
        with IOWrapper(certificate) as stream:
            while True:
                b = stream.read(1)
                if not b:
                    break
                b = ord(b[0]) & 0b11111111
                cert.append((b & 0b11110000) >> 4)
                cert.append(b & 0b00001111)
    with GzipIOWrapper(ciphertext) as stream:
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
                raw_length = bytearray(decrypt(stream, None, cert = cert, file_length = 8))
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
                for byte in cert[n:n+length]:
                    yield byte
                    num_bytes += 1
                    if file_length is not None and num_bytes >= file_length:
                        return

if __name__ == "__main__":
    import argparse
    
    copyright_message = "Copyright (C) 2012--2014, Evan A. Sultanik, Ph.D.  \nhttp://www.sultanik.com/\n"

    parser = argparse.ArgumentParser(description="A simple cryptosystem with provable plausible deniability.  " + copyright_message, prog="lenticrypt")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="append", nargs=2, type=argparse.FileType('r'), metavar=('secret', 'plaintext'), help="encrypts the given plaintext file(s) into a single ciphertext using the given secret file(s).  Additional secret/plaintext pairs can be specified by providing the `-e` option multiple times.  For example, `-e secret1 plaintext1 -e secret2 plaintext2 -e secret3 plaintext3 ...`.  If the `-l` argument is used, any plaintext that is longer than the first one provided will be truncated.  Any plaintext that is shorter than the first one provided will be tail-padded with zeros.")
    group.add_argument("-d", "--decrypt", nargs=2, type=str, metavar=('secret', 'ciphertext'), help="decrypts the ciphertext file using the given secret file")
    group.add_argument("-t", "--test", type=argparse.FileType('r'), nargs="+", metavar=('secret'), help="tests whether a given set of secrets have sufficient entropy to encrypt an equal number of plaintexts.  The exit code of the program is zero on success.  On failure, the missing byte combinations are printed to stdout.")
    
    parser.add_argument("-f", "--force-encrypt", action="store_true", default=False, help="force encryption, even if the secrets have insufficient entropy to correctly encrypt the plaintexts")
    parser.add_argument("-o", "--outfile", nargs='?', type=argparse.FileType('w'), default=sys.stdout, help="the output file (default to stdout)")
    parser.add_argument("-l", "--same-length", action="store_true", default=False, help="removes the header that is used to specify the length of the encrypted files.  The header solves the problem of having plaintexts of unequal length, so with this option enabled encryption might be lossy if the plaintexts are not the same length.  This option does slightly strengthen plausible deniability.")
    group.add_argument("-v", "--version", action="store_true", default=False, help="prints version information")
    parser.add_argument("-q", "--quiet", action="store_true", default=False, help="suppresses log messages")
    compression_group = parser.add_mutually_exclusive_group()
    compression_group.add_argument("-1","--fast", action="store_true", default=False)
    compression_group.add_argument("-2", dest="two", action="store_true", default=False)
    compression_group.add_argument("-3", dest="three", action="store_true", default=False)
    compression_group.add_argument("-4", dest="four", action="store_true", default=True)
    compression_group.add_argument("-5","--best", action="store_true", default=False, help="These options change the compression level used, with the -1 option being the fastest, with less compression, and the -5 option being the slowest, with best compression.  CPU and memory usage will increase exponentially as the compression level increases.  The default compression level is -4.")
    parser.add_argument("-s", "--seed", type=int, default=None, help="seeds the random number generator to the given value")

    args = parser.parse_args()
    
    if args.seed is not None:
        random.seed(args.seed)

    if args.version:
        sys.stdout.write("Cryptosystem Version: " + str(ENCRYPTION_VERSION / 10.0) + "\n" + copyright_message + "\n")
    elif args.encrypt:
        secrets = map(lambda s : bytearray(s[0].read()), args.encrypt)
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
        if not args.quiet:
            callback = ProgressBarCallback()
        try:
            substitution_alphabet = find_common_nibble_grams(secrets, nibble_gram_lengths = nibble_gram_lengths, status_callback = callback)
        except (KeyboardInterrupt, SystemExit):
            # die gracefully, without a stacktrace
            exit(1)
        finally:
            if callback is not None:
                callback.clear()
        if len(substitution_alphabet[1]) < 16**len(secrets):
            err_msg = "there is not sufficient coverage between the certificates to encrypt all possible bytes!\n"
            if args.force_encrypt:
                sys.stderr.write("Warning: " + err_msg)
            else:
                sys.stderr.write("Error: " + err_msg + "To supress this error, re-run with the `-f` option.\n")
                exit(1)
        # let the secret files be garbage collected, if needed:
        secrets = None
        callback = None
        if not args.quiet:
            callback = ProgressBarCallback()
        try:
            with gzip.GzipFile(fileobj=args.outfile, mtime=1) as zipfile:
                # mtime is set to 1 so that the output files are always identical if a random seed argument is provided
                #for byte in encrypt(substitution_alphabet, map(lambda e : e[1], args.encrypt), add_length_checksum = not args.same_length, status_callback = callback):
                for byte in DictionaryEncrypter(substitution_alphabet, map(lambda e : e[1], args.encrypt), status_callback = callback):
                    zipfile.write(byte)
        except (KeyboardInterrupt, SystemExit):
            # die gracefully, without a stacktrace
            exit(1)
        finally:
            if callback is not None:
                callback.clear()
    elif args.decrypt:
        try:
            for byte in decrypt(args.decrypt[1], args.decrypt[0]):
                args.outfile.write(chr(byte))
        except (KeyboardInterrupt, SystemExit):
            # die gracefully, without a stacktrace
            exit(1)
    elif args.test:
        secrets = map(lambda s : bytearray(s.read()), args.test)
        callback = None
        if not args.quiet:
            callback = ProgressBarCallback()
        try:
            substitution_alphabet = find_common_nibble_grams(secrets, nibble_gram_lengths = [1], status_callback = callback)
        except (KeyboardInterrupt, SystemExit):
            # die gracefully, without a stacktrace
            exit(1)
        finally:
            if callback is not None:
                callback.clear()
        if len(substitution_alphabet[1]) < 16**len(secrets):

            sys.stderr.write("There is not sufficient coverage between the certificates to encrypt all possible bytes!\nMissing byte combinations:\n")
            sys.stderr.flush()
            import itertools
            for combination in itertools.product(*[range(16) for i in range(len(secrets))]):
                if tuple(map(lambda c : (c,), combination)) not in substitution_alphabet[1]:
                    sys.stdout.write(str(tuple(map(chr, combination))) + "\n")
            exit(1)
        else:
            sys.stderr.write("This set of secrets looks good!\n")
            exit(0)
