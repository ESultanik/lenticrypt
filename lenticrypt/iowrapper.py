import collections.abc
import gzip
import sys

from io import BufferedReader, BytesIO, IOBase
from typing import BinaryIO, IO, Iterable, Union

IOWrappable = Union[bytes, bytearray, BinaryIO, Iterable[int]]


def get_length(stream: IO) -> int:
    """Gets the number of bytes in the stream."""
    old_position = stream.tell()
    stream.seek(0)
    length = 0
    try:
        while True:
            r = stream.read(1024)
            if not r:
                break
            length += len(r)
    finally:
        stream.seek(old_position)
    return length


class IOWrapper(collections.abc.Sequence):
    def __init__(self, wrapped: IOWrappable):
        self.wrapped = wrapped
        self._file = None

    def new_instance(self):
        if self.wrapped == '-':
            return sys.stdin
        elif isinstance(self.wrapped, IOWrapper):
            return self.wrapped.new_instance()
        elif isinstance(self.wrapped, IOBase):
            return self.wrapped
        elif isinstance(self.wrapped, collections.abc.Iterable):
            if not isinstance(self.wrapped, bytes) and not isinstance(self.wrapped, bytearray):
                return BytesIO(bytes([b for b in self.wrapped]))
            else:
                return BytesIO(self.wrapped)
        else:
            return open(self.wrapped, 'rb')

    def __len__(self):
        if isinstance(self.wrapped, collections.abc.Sized):
            return len(self.wrapped)
        else:
            with self.new_instance() as f:
                return get_length(f)

    def __getitem__(self, index: Union[slice, int]) -> Union[int, bytes]:
        if isinstance(self.wrapped, collections.abc.Sequence):
            return self.wrapped[index]
        else:
            with self.new_instance() as f:
                old_position = f.tell()
                try:
                    if isinstance(index, slice):
                        if index.start is None:
                            index = slice(0, index.stop, index.step)
                        if index.stop is None:
                            index = slice(index.start, len(self), index.step)
                        if index.step is None or index.step == 1:
                            f.seek(index.start)
                            return f.read(index.stop - index.start)
                        else:
                            ret = bytearray()
                            for i in range(index.start, index.stop, index.step):
                                f.seek(i)
                                r = f.read(1)
                                if r is None or len(r) < 1:
                                    break
                                ret.append(r)
                            return bytes(ret)
                    else:
                        r = f.read(1)
                        if r is None or len(r) < 1:
                            return None
                        else:
                            return r[0]
                finally:
                    f.seek(old_position)

    def __enter__(self):
        f = self.new_instance()
        if f is not self.wrapped:
            self._file = f
        return f.__enter__()

    def __exit__(self, type, value, tb):
        if self._file is not None:
            self._file.__exit__(type, value, tb)
            self._file = None


class GzipIOWrapper(IOWrapper):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def new_instance(self):
        return gzip.GzipFile(fileobj=super().new_instance())


GZIP_MAGIC = b'\x1F\x8B'


class AutoUnzippingStream:
    def __init__(self, stream: IOWrappable):
        self.__stream = stream
        self.__to_close = None

    def __enter__(self):
        if self.__to_close is not None:
            raise Exception(f"{self!r} is already a context manager")
        stream = IOWrapper(self.__stream)
        reader = BufferedReader(stream.__enter__())
        to_close = [reader]
        if reader.peek(len(GZIP_MAGIC)) == GZIP_MAGIC:
            ret = GzipIOWrapper(reader)
            to_close.append(ret)
            ret = ret.__enter__()
        else:
            ret = reader
        self.__to_close = (stream,) + tuple(to_close)
        return ret

    def __exit__(self, *args, **kwargs):
        try:
            for stream in self.__to_close:
                stream.__exit__(*args, **kwargs)
        finally:
            self.__to_close = None
