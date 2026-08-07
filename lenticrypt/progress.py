import shutil
import sys
from typing import IO, Protocol, runtime_checkable


@runtime_checkable
class StatusCallback(Protocol):
    """What the encrypters and the index builder expect of a progress reporter."""

    def __call__(self, value: int, max_value: int, status: str | None = None) -> None: ...


class StatusLine:
    """A single terminal line that can be overwritten in place."""

    def __init__(self, stream: IO = sys.stderr) -> None:
        self.stream = stream
        self.clear()

    def clear(self) -> None:
        width, _height = shutil.get_terminal_size()
        self.stream.write(f"\r{' ' * width}\r")

    def write(self, text: str) -> None:
        self.stream.write(text)

    def flush(self) -> None:
        self.stream.flush()


class ProgressBar(StatusLine):
    def __init__(
        self,
        starting_value: int = 0,
        max_value: int = 100,
        stream: IO = sys.stderr,
    ) -> None:
        super().__init__(stream)
        self.max_value = max_value
        self.value = starting_value
        self._last_percent = -1
        self._last_status: str | None = None

    def update(self, value: int, status: str | None = None, max_value: int | None = None) -> None:
        """Redraws the bar, but only when the rendered result would actually differ.

        `max_value` may be supplied per call. `ProgressBarCallback` used to bind it once from its
        first call, so every later phase was drawn against the first phase's scale.
        """
        if max_value is not None:
            self.max_value = max_value
        self.value = value
        # A zero maximum is reachable: the index builder derives its range from the certificate
        # length, which is <= 0 for a short certificate and a long nibble-gram. This used to raise
        # ZeroDivisionError.
        percent = 1.0 if self.max_value <= 0 else min(max(value / self.max_value, 0.0), 1.0)
        rounded = int(percent * 100.0 + 0.5)
        if rounded == self._last_percent and status == self._last_status:
            return
        self._last_percent = rounded
        self._last_status = status
        self.clear()
        self.write(self._render(percent, rounded, status))
        self.flush()

    def _render(self, percent: float, rounded: int, status: str | None) -> str:
        """Builds the whole bar as one string.

        This used to issue one `stream.write()` per column, so a 200-column terminal cost 200 write
        calls per redraw.
        """
        width = max(shutil.get_terminal_size().columns - 2, 1)
        filled = int(width * percent + 0.5)
        label = (f"{status} {rounded}%" if status else f"{rounded}%")[:width]
        start = max((width - len(label)) // 2, 0)
        # Spaces inside the label that fall within the filled region become bar characters, so the
        # label stays legible without punching a hole in the bar.
        labelled = "".join(
            "=" if character == " " and start + offset < filled else character
            for offset, character in enumerate(label)
        )
        left = "".join("=" if i < filled else "-" for i in range(start))
        right = "".join("=" if i < filled else "-" for i in range(start + len(label), width))
        return f"[{left}{labelled}{right}]"


class ProgressBarCallback:
    """Adapts `ProgressBar` to the `StatusCallback` protocol, creating the bar on first use."""

    def __init__(self, stream: IO = sys.stderr) -> None:
        self.stream = stream
        self.pb: ProgressBar | None = None

    def __call__(self, value: int, max_value: int, status: str | None = None) -> None:
        if self.pb is None:
            self.pb = ProgressBar(max_value=max_value, stream=self.stream)
        self.pb.update(value, status, max_value=max_value)

    def clear(self) -> None:
        if self.pb is not None:
            self.pb.clear()

    def __enter__(self) -> "ProgressBarCallback":
        return self

    def __exit__(self, *_args: object) -> None:
        self.clear()
