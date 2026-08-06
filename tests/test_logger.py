"""ColorFormatter output, with and without colour.

This module had no tests, so the placeholder expansion and the INFO special case were unverified.
"""

import logging

import pytest

from lenticrypt.logger import DEFAULT_FORMAT, ColorFormatter, ansi_color
from lenticrypt.utils import ANSI_RESET, CGAColors

ESCAPE = "\033"


def record(level: int, message: str = "hello") -> logging.LogRecord:
    return logging.LogRecord("lenticrypt", level, __file__, 1, message, None, None)


def test_info_is_printed_bare():
    """INFO is the ordinary case: no level name, no escapes."""
    formatter = ColorFormatter(DEFAULT_FORMAT, use_color=True)
    assert formatter.format(record(logging.INFO)) == "hello"


@pytest.mark.parametrize("level", [logging.WARNING, logging.ERROR, logging.CRITICAL, logging.DEBUG])
def test_other_levels_are_labelled_and_coloured(level):
    formatter = ColorFormatter(DEFAULT_FORMAT, use_color=True)
    output = formatter.format(record(level))
    assert logging.getLevelName(level) in output
    assert ESCAPE in output
    assert "hello" in output


@pytest.mark.parametrize(
    "level", [logging.WARNING, logging.ERROR, logging.CRITICAL, logging.DEBUG, logging.INFO]
)
def test_no_escapes_when_colour_is_disabled(level):
    """Redirected output must stay free of escape sequences."""
    formatter = ColorFormatter(DEFAULT_FORMAT, use_color=False)
    output = formatter.format(record(level))
    assert ESCAPE not in output
    assert "$" not in output
    assert "hello" in output


@pytest.mark.parametrize("level", [logging.WARNING, logging.ERROR, logging.CRITICAL])
def test_level_is_still_named_when_colour_is_disabled(level):
    """Redirecting stderr used to discard the level entirely, so an ERROR read as ordinary text."""
    formatter = ColorFormatter(DEFAULT_FORMAT, use_color=False)
    assert logging.getLevelName(level) in formatter.format(record(level))


def test_info_stays_bare_without_colour():
    """INFO is conversational at any colour setting."""
    formatter = ColorFormatter(DEFAULT_FORMAT, use_color=False)
    assert formatter.format(record(logging.INFO)) == "hello"


def test_level_colour_placeholder_is_resolved_per_record():
    """`$LEVELCOLOR` must become the colour of *this* record's level, not a fixed one."""
    formatter = ColorFormatter(DEFAULT_FORMAT, use_color=True)
    warning = formatter.format(record(logging.WARNING))
    error = formatter.format(record(logging.ERROR))
    assert "$LEVELCOLOR" not in warning
    assert ansi_color(CGAColors.YELLOW) in warning
    assert ansi_color(CGAColors.RED) in error


def test_multiline_messages_get_continuation_markers():
    formatter = ColorFormatter(DEFAULT_FORMAT, use_color=True)
    output = formatter.format(record(logging.WARNING, "first\nsecond\nthird"))
    assert "first" in output
    assert "second" in output
    assert "third" in output
    assert output.count("\n") >= 2


def test_named_colour_placeholders_expand():
    assert ansi_color(CGAColors.BLUE) in ColorFormatter.expand("$BLUE")
    assert ColorFormatter.expand("$RESET") == ANSI_RESET


def test_strip_removes_every_placeholder():
    fmt = "$RESET$LEVELCOLOR$BOLD$RED$GREEN%(message)s"
    assert ColorFormatter.strip(fmt) == "%(message)s"


def test_usable_as_a_real_handler_formatter(capsys):
    """End to end through logging itself, which is how __main__ wires it up."""
    logger = logging.getLogger("lenticrypt.test_logger")
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(ColorFormatter(DEFAULT_FORMAT, use_color=False))
    logger.addHandler(handler)
    logger.warning("careful")
    logger.info("routine")
    captured = capsys.readouterr().err
    assert "WARNING" in captured
    assert "careful" in captured
    assert "routine" in captured
    logger.handlers.clear()
