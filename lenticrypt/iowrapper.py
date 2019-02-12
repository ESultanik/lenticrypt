import collections.abc
import gzip

from io import BytesIO, IOBase

from typing import BinaryIO, IO, Iterable, Union


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
    def __init__(self, wrapped: Union[bytes, bytearray, BinaryIO, Iterable[int]]):
        self.wrapped = wrapped
        self._file = None

    def new_instance(self):
        if self.wrapped == '-':
            return sys.stdin
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

    def __getitem__(self, index):
        if isinstance(self.wrapped, collections.abc.Sequence):
            return self.wrapped[index]
        else:
            with self.new_instance() as f:
                old_position = f.tell()
                f.seek(index)
                try:
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
