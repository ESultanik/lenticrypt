import logging
from collections.abc import Mapping
from typing import Any, Literal

from .utils import ANSI_BOLD, ANSI_RESET, CGAColors

LEVEL_COLORS = {
    logging.CRITICAL: CGAColors.MAGENTA,
    logging.ERROR: CGAColors.RED,
    logging.WARNING: CGAColors.YELLOW,
    logging.INFO: CGAColors.GREEN,
    logging.DEBUG: CGAColors.CYAN,
    logging.NOTSET: CGAColors.BLUE,
}

DEFAULT_FORMAT = "$RESET$LEVELCOLOR$BOLD%(levelname)-8s$RESET %(message)s"

# Placeholder substituted with the colour of the record's own level, rather than a fixed colour.
LEVEL_COLOR_PLACEHOLDER = "$LEVELCOLOR"


def ansi_color(color: CGAColors) -> str:
    """The ANSI escape that selects `color` as the foreground."""
    return f"\033[1;{30 + color.value}m"


class ColorFormatter(logging.Formatter):
    """Expands `$COLOR`, `$BOLD` and `$RESET` placeholders in a log format.

    Subclasses `logging.Formatter` directly. It previously went through a `ComposableFormatter` that
    wrapped a formatter and forwarded everything through `__getattr__`, which returns `Any` and so
    silently disabled type checking on every delegated attribute -- for a single level of
    composition that was never reused.
    """

    def __init__(
        self,
        fmt: str = DEFAULT_FORMAT,
        datefmt: str | None = None,
        style: Literal["%", "{", "$"] = "%",
        validate: bool = True,
        *,
        defaults: Mapping[str, Any] | None = None,
        use_color: bool = True,
    ) -> None:
        # `logging.Formatter`'s parameters are spelled out rather than forwarded through
        # `*args, **kwargs`, which typed them as `object` and needed a blanket ignore.
        self._use_color = use_color
        expand = self.expand if use_color else self.strip
        super().__init__(
            expand(fmt),
            expand(datefmt) if datefmt else datefmt,
            style,
            validate,
            defaults=defaults,
        )

    @staticmethod
    def expand(fmt: str) -> str:
        """Replaces colour placeholders with ANSI escapes, leaving `$LEVELCOLOR` for `format`."""
        for color in CGAColors:
            fmt = fmt.replace(f"${color.name}", ansi_color(color))
        return fmt.replace("$RESET", ANSI_RESET).replace("$BOLD", ANSI_BOLD)

    @staticmethod
    def strip(fmt: str) -> str:
        """Removes every colour placeholder, for non-tty output."""
        for color in CGAColors:
            fmt = fmt.replace(f"${color.name}", "")
        for placeholder in ("$RESET", "$BOLD", LEVEL_COLOR_PLACEHOLDER):
            fmt = fmt.replace(placeholder, "")
        return fmt

    def format(self, record: logging.LogRecord) -> str:
        # INFO is the ordinary, conversational case, so it is printed bare: no level name.
        if record.levelno == logging.INFO:
            return record.getMessage()
        if not self._use_color:
            # Colour off still means *labelled*. Previously this returned the bare message for every
            # level, so redirecting stderr to a file silently discarded the fact that a message was
            # a WARNING or an ERROR. The placeholders are already stripped from the format string.
            return super().format(record)
        level_color = ansi_color(LEVEL_COLORS.get(record.levelno, LEVEL_COLORS[logging.NOTSET]))
        formatted = super().format(record).replace(LEVEL_COLOR_PLACEHOLDER, level_color)
        # Multi-line messages get a continuation marker, so a wrapped warning reads as one record.
        formatted = formatted.replace("\n", self.expand("$RESET $BOLD$BLUE\\$RESET\n"), 1)
        return formatted.replace("\n", self.expand("\n$RESET$BOLD$BLUE> $RESET"))
