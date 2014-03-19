#!/usr/bin/env python2

import sys, itertools, random, struct, StringIO, gzip

ENCRYPTION_VERSION = 2

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

def find_common_nibble_grams(certificates, nibble_gram_lengths = [1, 2, 4, 8, 16]):
    all_nibbles = {} # maps a nibble value to a common index
    for nibble_gram_length in nibble_gram_lengths:
        nibbles = {}
        all_nibbles[nibble_gram_length] = nibbles
        for index in range(0,min(map(len, certificates))*2 - nibble_gram_length + 1):
            pair = tuple(map(lambda c : read_nibble_gram(c, index, nibble_gram_length), certificates))
            if pair in nibbles:
                nibbles[pair].append(index)
            else:
                nibbles[pair] = [index]
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

# block header, 8 bits:
# MSB -> X X X X X X X X <- LSB
#                 |-----| <-- index_bytes - 1 (since index_bytes is always greater than zero)
#         |-------| <-- length - 1 (since length is always greater than zero)
#       |-| <-- If 1, then the following 7 bits are a filetype version number and the following blocks are the encrypted 8 bytes encoding the length of the file
def encrypt(substitution_alphabet, to_encrypt, add_length_checksum=False):
    if add_length_checksum:
        block_header = 0b10000000 | ENCRYPTION_VERSION # the magic length checksum bit and filetype version number
        yield chr(block_header)
        lengths = map(lambda l : StringIO.StringIO(struct.pack("<Q", l)), map(get_length, to_encrypt))
        for b in encrypt(substitution_alphabet, lengths, add_length_checksum=False):
            yield b
    sorted_lengths = sorted(substitution_alphabet.keys(), reverse=True)
    buffers = [BufferedNibbleGramReader(e, sorted_lengths[0]) for e in to_encrypt]
    if add_length_checksum:
        completion_test = lambda : sum(map(lambda b : not b.eof(), buffers))
    else:
        completion_test = lambda : buffers[0]
    while completion_test():
        # if the files are not the same length, encrypt to the length of to_encrypt1
        for length in sorted_lengths:
            ng = []
            for i, b in enumerate(buffers):
                n = b.peek_nibbles(length)
                if n is None and (i > 0 or add_length_checksum):
                    # this will happen if this plaintext is shorter than the first plaintext; just pad its tail with zeros
                    n = tuple([0]*length)
                ng.append(n)
            if ng[0] is None and not add_length_checksum:
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
                yield struct.pack("<B" + index_type, block_header, index)
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

class IOWrapper:
    def __init__(self, wrapped):
        self.wrapped = wrapped
        self._file = None
    def __enter__(self):
        if isinstance(self.wrapped, StringIO.StringIO) or isinstance(self.wrapped, gzip.GzipFile) or isinstance(self.wrapped, file):
            return self.wrapped
        else:
            self._file = gzip.GzipFile(self.wrapped)
            return self._file.__enter__()
    def __exit__(self, type, value, tb):
        if self._file is not None:
            self._file.__exit__(type, value, tb)

def decrypt(ciphertext_file, certificate_file, cert = None, file_length = None):
    # the file format is specified in a comment at the top of the encrypt(...) function above.
    if cert is None:
        cert = []
        with open(certificate_file) as stream:
            while True:
                b = stream.read(1)
                if not b:
                    break
                b = ord(b[0]) & 0b11111111
                cert.append((b & 0b11110000) >> 4)
                cert.append(b & 0b00001111)
    with IOWrapper(ciphertext_file) as stream:
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
                    sys.stderr.write("Warning: This ciphertext appears to have been encrypted with a newer version of the cryptosystem (version " + (version / 10.0) + ").\n")
                # the next 8 encrypted bytes encode the length of the plaintext
                raw_length = bytearray(decrypt(stream, None, cert = cert, file_length = 8))
                file_length = struct.unpack("<Q", raw_length)[0]
                sys.stderr.write("Plaintext file length is " + str(file_length) + " bytes\n")
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

    parser = argparse.ArgumentParser(description="A simple cryptosystem with provable plausible deniability.  " + copyright_message)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="append", nargs=2, type=argparse.FileType('r'), metavar=('secret', 'plaintext'), help="encrypts the given plaintext file(s) into a single ciphertext using the given secret file(s).  Additional secret/plaintext pairs can be specified by providing the `-e` option multiple times.  For example, `-e secret1 plaintext1 -e secret2 plaintext2 -e secret3 plaintext3 ...`.  If the `-l` argument is used, any plaintext that is longer than the first one provided will be truncated.  Any plaintext that is shorter than the first one provided will be tail-padded with zeros.")
    group.add_argument("-d", "--decrypt", nargs=2, type=str, metavar=('secret', 'ciphertext'), help="decrypts the ciphertext file using the given secret file")
    group.add_argument("-t", "--test", type=argparse.FileType('r'), nargs="+", metavar=('secret'), help="tests whether a given set of secrets have sufficient entropy to encrypt an equal number of plaintexts.  The exit code of the program is zero on success.  On failure, the missing byte combinations are printed to stdout.")
    
    parser.add_argument("-f", "--force-encrypt", action="store_true", default=False, help="force encryption, even if the secrets have insufficient entropy to correctly encrypt the plaintexts")
    parser.add_argument("-o", "--outfile", nargs='?', type=argparse.FileType('w'), default=sys.stdout, help="the output file (default to stdout)")
    parser.add_argument("-l", "--same-length", action="store_true", default=False, help="removes the header that is used to specify the length of the encrypted files.  The solves the problem of having plaintexts of unequal length.  Without it, encryption might be lossy if the plaintexts are not the same length, however, there is slightly greater plausible deniability.")
    group.add_argument("-v", "--version", action="store_true", default=False, help="prints version information")

    args = parser.parse_args()

    if args.version:
        sys.stdout.write("Cryptosystem Version: " + str(ENCRYPTION_VERSION / 10.0) + "\n" + copyright_message + "\n")
    elif args.encrypt:
        secrets = map(lambda s : bytearray(s[0].read()), args.encrypt)
        substitution_alphabet = find_common_nibble_grams(secrets)
        if len(substitution_alphabet[1]) < 16**len(secrets):
            err_msg = "there is not sufficient coverage between the certificates to encrypt all possible bytes!\n"
            if args.force_encrypt:
                sys.stderr.write("Warning: " + err_msg)
            else:
                sys.stderr.write("Error: " + err_msg + "To supress this error, re-run with the `-f` option.\n")
                exit(1)
        # let the secret files be garbage collected, if needed:
        secrets = None
        with gzip.GzipFile(fileobj=args.outfile) as zipfile:
            for byte in encrypt(substitution_alphabet, map(lambda e : e[1], args.encrypt), add_length_checksum = not args.same_length):
                zipfile.write(byte)
    elif args.decrypt:
        for byte in decrypt(args.decrypt[1], args.decrypt[0]):
            args.outfile.write(chr(byte))
    elif args.test:
        secrets = map(lambda s : bytearray(s.read()), args.test)
        substitution_alphabet = find_common_nibble_grams(secrets)
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
