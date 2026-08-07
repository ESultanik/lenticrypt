"""IOWrapper and auto_unzip.

Neither had any tests. `IOWrapper` claims to be a `collections.abc.Sequence`, but dispatched on
`isinstance(..., Sequence)` at call time -- and `str` is itself a Sequence, so for a file path both
`len()` and `[]` operated on the path text rather than the file.
"""

import gzip
import io
import subprocess
import sys

import pytest

from lenticrypt.exceptions import LenticryptError
from lenticrypt.iowrapper import IOWrapper, auto_unzip, get_length

CONTENT = bytes(range(20))


@pytest.fixture
def path(tmp_path):
    target = tmp_path / "twenty-bytes.bin"
    target.write_bytes(CONTENT)
    return target


@pytest.fixture(params=["path", "str-path", "bytes", "bytearray", "stream", "int-iterable"])
def source(request, path):
    """Every kind of thing IOWrappable claims to accept."""
    return {
        "path": path,
        "str-path": str(path),
        "bytes": CONTENT,
        "bytearray": bytearray(CONTENT),
        "stream": io.BytesIO(CONTENT),
        "int-iterable": iter(CONTENT),
    }[request.param]


def test_len_reflects_the_content(source):
    """For a path this used to return the length of the path string."""
    assert len(IOWrapper(source)) == len(CONTENT)


def test_integer_index_reflects_the_content(source):
    """For a path this used to index the path string; for a stream it never seeked."""
    wrapper = IOWrapper(source)
    assert wrapper[5] == CONTENT[5]
    assert wrapper[0] == CONTENT[0]
    assert wrapper[len(CONTENT) - 1] == CONTENT[-1]


def test_negative_index(source):
    assert IOWrapper(source)[-1] == CONTENT[-1]


def test_out_of_range_index_raises_index_error(source):
    with pytest.raises(IndexError):
        IOWrapper(source)[len(CONTENT)]


def test_contiguous_slice(source):
    assert IOWrapper(source)[4:12] == CONTENT[4:12]


def test_stepped_slice(source):
    """`bytearray.append` needs an int; this appended a one-byte `bytes` and raised TypeError."""
    assert IOWrapper(source)[0:10:2] == CONTENT[0:10:2]


def test_open_ended_slices(source):
    wrapper = IOWrapper(source)
    assert wrapper[:5] == CONTENT[:5]
    assert wrapper[15:] == CONTENT[15:]
    assert wrapper[:] == CONTENT


def test_context_manager_yields_the_content(source):
    with IOWrapper(source) as stream:
        assert stream.read() == CONTENT


def test_caller_supplied_stream_is_not_closed():
    """We only close handles we opened."""
    stream = io.BytesIO(CONTENT)
    with IOWrapper(stream) as opened:
        assert opened is stream
    assert not stream.closed


def test_unsupported_source_is_rejected():
    with pytest.raises(LenticryptError):
        IOWrapper(object())  # type: ignore[arg-type]


def test_stdin_is_read_as_binary_and_left_open():
    """`IOWrapper('-')` returned the *text* sys.stdin, and closed it on exit.

    Reading bytes from the text stream yields `str`, and callers immediately do bit arithmetic on
    the result. Run in a subprocess so a real stdin is involved.
    """
    program = """
import sys
from lenticrypt.iowrapper import IOWrapper
with IOWrapper('-') as stream:
    data = stream.read()
assert isinstance(data, bytes), type(data)
assert not sys.stdin.closed, "sys.stdin was closed"
print("ok", len(data))
"""
    result = subprocess.run(  # noqa: S603 -- our own interpreter, fixed program
        [sys.executable, "-c", program],
        input=CONTENT,
        capture_output=True,
        check=True,
    )
    assert result.stdout.strip() == b"ok 20", result.stderr


class TestGetLength:
    def test_seekable_stream(self):
        assert get_length(io.BytesIO(CONTENT)) == len(CONTENT)

    def test_restores_the_position(self):
        stream = io.BytesIO(CONTENT)
        stream.seek(7)
        get_length(stream)
        assert stream.tell() == 7

    def test_empty_stream(self):
        assert get_length(io.BytesIO(b"")) == 0


class TestAutoUnzip:
    def test_plain_data_passes_through(self):
        with auto_unzip(CONTENT) as stream:
            assert stream.read() == CONTENT

    def test_gzipped_data_is_decompressed(self):
        with auto_unzip(gzip.compress(CONTENT)) as stream:
            assert stream.read() == CONTENT

    def test_gzipped_file_is_decompressed(self, tmp_path):
        target = tmp_path / "compressed.gz"
        target.write_bytes(gzip.compress(CONTENT))
        with auto_unzip(str(target)) as stream:
            assert stream.read() == CONTENT

    def test_single_byte_reads_work(self):
        """The varint decoder reads one byte at a time, so this is the hot path."""
        with auto_unzip(gzip.compress(CONTENT)) as stream:
            assert b"".join(iter(lambda: stream.read(1), b"")) == CONTENT
