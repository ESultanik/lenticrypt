"""Progress bar rendering and portability.

This module had no tests. It also made the whole package unimportable on Windows, by importing
`fcntl` and `termios` at module scope.
"""

import io
import os
import sys

import pytest

from lenticrypt.progress import ProgressBar, ProgressBarCallback, StatusCallback

TERMINAL_WIDTH = 40


@pytest.fixture(autouse=True)
def _fixed_width(monkeypatch):
    """Pins the terminal width so rendered output is comparable."""
    monkeypatch.setattr(
        "shutil.get_terminal_size", lambda *_: os.terminal_size((TERMINAL_WIDTH, 24))
    )


def test_zero_max_value_does_not_divide_by_zero():
    """The index builder computes a range of <= 0 for a short certificate and a long gram."""
    ProgressBar(max_value=0, stream=io.StringIO()).update(0)


def test_negative_max_value_does_not_raise():
    ProgressBar(max_value=-5, stream=io.StringIO()).update(3)


def test_renders_status_and_percentage():
    stream = io.StringIO()
    ProgressBar(max_value=10, stream=stream).update(5, "Encrypting")
    output = stream.getvalue()
    assert "Encrypting" in output
    assert "50%" in output


def test_bar_fits_the_terminal_width():
    stream = io.StringIO()
    ProgressBar(max_value=10, stream=stream).update(5, "Encrypting")
    # The last written line, without the leading clear sequence.
    line = stream.getvalue().rsplit("\r", 1)[-1]
    assert len(line) == TERMINAL_WIDTH  # interior plus the two brackets
    assert line.startswith("[")
    assert line.endswith("]")


def test_clamps_out_of_range_values():
    stream = io.StringIO()
    bar = ProgressBar(max_value=10, stream=stream)
    bar.update(-5)
    assert "0%" in stream.getvalue()
    bar.update(999)
    assert "100%" in stream.getvalue()


def test_rescales_when_max_value_changes():
    """Each phase reports its own maximum; the bar must not stay on the first one's scale."""
    stream = io.StringIO()
    callback = ProgressBarCallback(stream=stream)
    callback(50, 100, "PhaseOne")
    callback(50, 1000, "PhaseTwo")
    output = stream.getvalue()
    # Spaces inside a label become bar characters where the bar is filled, so the labels here are
    # deliberately space-free.
    assert "PhaseOne 50%" in output or "PhaseOne=50%" in output
    assert "PhaseTwo 5%" in output or "PhaseTwo=5%" in output


def test_redraw_is_skipped_when_nothing_would_change():
    stream = io.StringIO()
    bar = ProgressBar(max_value=1000, stream=stream)
    bar.update(500, "Working")
    before = len(stream.getvalue())
    bar.update(501, "Working")  # same rounded percentage
    assert len(stream.getvalue()) == before


def test_callback_satisfies_the_protocol():
    assert isinstance(ProgressBarCallback(stream=io.StringIO()), StatusCallback)


def test_callback_is_a_context_manager():
    stream = io.StringIO()
    with ProgressBarCallback(stream=stream) as callback:
        callback(1, 10, "Working")
    assert "Working" in stream.getvalue()


def test_importable_without_unix_terminal_modules(monkeypatch):
    """`fcntl` and `termios` are Unix-only; importing them at module scope broke Windows."""
    for module in ("fcntl", "termios"):
        monkeypatch.setitem(sys.modules, module, None)
    import importlib

    import lenticrypt.progress

    importlib.reload(lenticrypt.progress)
    assert lenticrypt.progress.ProgressBar is not None
