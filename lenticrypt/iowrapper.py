import collections.abc
import enum
import gzip
import os
import sys
from collections.abc import Iterable, Iterator
from contextlib import ExitStack, contextmanager, suppress
from io import SEEK_END, BufferedReader, BytesIO, IOBase, RawIOBase
from pathlib import Path
from typing import IO, BinaryIO, TypeAlias, Union, cast, overload

from .exceptions import LenticryptError

IOWrappable = Union[str, "os.PathLike[str]", bytes, bytearray, BinaryIO, Iterable[int]]

GZIP_MAGIC = b"\x1f\x8b"

# Read granularity for the length fallback used on non-seekable streams.
LENGTH_CHUNK_BYTES = 1 << 20

# `-` means "standard input" throughout the CLI.
STDIN_ARGUMENT = "-"


def get_length(stream: IO) -> int:
    """Returns the number of bytes in the stream, restoring the original position.

    Seeks to the end when the stream supports it. The previous implementation always read the whole
    stream in 1 KiB chunks, which for a seekable file is O(n) I/O to learn something the OS already
    knows.
    """
    old_position = stream.tell()
    try:
        with suppress(OSError, ValueError):
            return stream.seek(0, SEEK_END)
        # Not seekable: fall back to reading, in large chunks rather than 1 KiB.
        stream.seek(0)
        length = 0
        while True:
            chunk = stream.read(LENGTH_CHUNK_BYTES)
            if not chunk:
                return length
            length += len(chunk)
    finally:
        stream.seek(old_position)


class _Kind(enum.Enum):
    """How an `IOWrappable` should be materialised."""

    PATH = enum.auto()
    STDIN = enum.auto()
    STREAM = enum.auto()
    BYTES = enum.auto()


_Source: TypeAlias = Union[str, "os.PathLike[str]", bytes, IO, None]


def _classify(wrapped: IOWrappable) -> tuple["_Kind", _Source]:
    """Decides once, up front, what kind of source this is.

    Dispatching per call on `isinstance(..., Sequence)` was the root of two bugs: `str` is itself a
    `Sequence`, so a file path satisfied every sequence check and `len()`/`[]` silently operated on
    the path text instead of the file's contents.
    """
    if isinstance(wrapped, IOWrapper):
        return wrapped._kind, wrapped._source
    if isinstance(wrapped, (bytes, bytearray)):
        return _Kind.BYTES, bytes(wrapped)
    if isinstance(wrapped, (str, os.PathLike)):
        if wrapped == STDIN_ARGUMENT:
            return _Kind.STDIN, None
        return _Kind.PATH, wrapped
    if isinstance(wrapped, IOBase) or hasattr(wrapped, "read"):
        # Duck-typed on purpose: anything with .read() is usable here. The cast records that we
        # have checked, since `hasattr` narrowing yields a structural type rather than a nominal IO.
        return _Kind.STREAM, cast("IO", wrapped)
    if isinstance(wrapped, collections.abc.Iterable):
        # An iterable of ints, e.g. a tee'd encrypter output. Materialised, since it cannot be
        # re-read.
        return _Kind.BYTES, bytes(wrapped)
    message = f"Cannot read from {wrapped!r}"
    raise LenticryptError(message)


class IOWrapper(collections.abc.Sequence):
    """Presents any supported source as a re-openable, indexable sequence of bytes."""

    def __init__(self, wrapped: IOWrappable) -> None:
        self.wrapped = wrapped
        self._kind, self._source = _classify(wrapped)
        self._file: IO | None = None
        self._owned = False
        self._length: int | None = None

    def _as_path(self) -> Union[str, "os.PathLike[str]"]:
        """The source as a filesystem path, validated rather than assumed."""
        if isinstance(self._source, (str, os.PathLike)):
            return self._source
        message = f"{self!r} is not backed by a path"
        raise LenticryptError(message)

    def _as_bytes(self) -> bytes:
        if isinstance(self._source, bytes):
            return self._source
        message = f"{self!r} is not backed by bytes"
        raise LenticryptError(message)

    def _as_stream(self) -> IO:
        if self._source is not None and hasattr(self._source, "read"):
            return cast("IO", self._source)
        message = f"{self!r} is not backed by a stream"
        raise LenticryptError(message)

    def new_instance(self) -> IO:
        """Opens a fresh handle on the source. Whether we own it is recorded for `__exit__`."""
        if self._kind is _Kind.STDIN:
            # The *binary* buffer: reading bytes from the text stream yields str, and the callers
            # immediately do arithmetic on the result.
            self._owned = False
            return getattr(sys.stdin, "buffer", sys.stdin)
        if self._kind is _Kind.STREAM:
            self._owned = False
            return self._as_stream()
        if self._kind is _Kind.BYTES:
            self._owned = True
            return BytesIO(self._as_bytes())
        self._owned = True
        return Path(self._as_path()).open("rb")

    def __len__(self) -> int:
        if self._length is None:
            if self._kind is _Kind.BYTES:
                self._length = len(self._as_bytes())
            elif self._kind is _Kind.PATH:
                self._length = Path(self._as_path()).stat().st_size
            else:
                with self as stream:
                    self._length = get_length(stream)
        return self._length

    @overload
    def __getitem__(self, index: int) -> int: ...

    @overload
    def __getitem__(self, index: slice) -> bytes: ...

    def __getitem__(self, index: int | slice) -> int | bytes:
        if self._kind is _Kind.BYTES:
            return self._as_bytes()[index]
        with self as stream:
            if isinstance(index, slice):
                return self._read_slice(stream, index)
            return self._read_one(stream, index)

    def _read_one(self, stream: IO, index: int) -> int:
        """Reads a single byte at `index`.

        The previous implementation never seeked, so every integer index returned byte 0.
        """
        if index < 0:
            index += len(self)
        if not 0 <= index < len(self):
            raise IndexError(index)
        stream.seek(index)
        data = stream.read(1)
        if not data:
            raise IndexError(index)
        return data[0]

    def _read_slice(self, stream: IO, index: slice) -> bytes:
        start, stop, step = index.indices(len(self))
        if step == 1:
            stream.seek(start)
            return stream.read(max(stop - start, 0))
        # `bytearray.append` needs an int; the previous code appended the one-byte `bytes` object
        # straight from `read(1)`, which raised TypeError.
        result = bytearray()
        for position in range(start, stop, step):
            stream.seek(position)
            data = stream.read(1)
            if not data:
                break
            result.append(data[0])
        return bytes(result)

    def __enter__(self) -> IO:
        stream = self.new_instance()
        # Only track handles we opened. Recording any handle that merely differed from
        # `self.wrapped` meant `IOWrapper('-')` closed sys.stdin on exit.
        self._file = stream if self._owned else None
        return stream

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None


@contextmanager
def auto_unzip(source: IOWrappable) -> Iterator[BinaryIO]:
    """Yields a buffered reader over `source`, transparently gunzipping it if it is gzipped.

    Buffering sits *on top* of the gzip layer, which is where it matters: the varint decoder reads
    one byte at a time, and unbuffered single-byte reads straight from a `GzipFile` are far slower.
    Torn down with an ExitStack, so layers close outermost-first; the class this replaces closed
    the underlying stream before the gzip wrapper.
    """
    with ExitStack() as stack:
        wrapper = IOWrapper(source)
        raw = cast("RawIOBase", stack.enter_context(wrapper))
        reader = stack.enter_context(BufferedReader(raw))
        if reader.peek(len(GZIP_MAGIC))[: len(GZIP_MAGIC)] == GZIP_MAGIC:
            unzipped = stack.enter_context(gzip.GzipFile(fileobj=reader, mode="rb"))
            yield stack.enter_context(BufferedReader(cast("RawIOBase", unzipped)))
        else:
            yield reader
