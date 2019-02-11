import fcntl
import os
import struct
import sys
import termios

from typing import IO, Optional, Tuple


def get_terminal_size() -> Tuple[int, int]:
    env = os.environ

    def ioctl_GWINSZ(fd):
        try:
            cr = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ, '1234'))
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
    def __init__(self, stream: IO = sys.stderr):
        self.stream = stream
        self.clear()

    def clear(self):
        width, height = get_terminal_size()
        self.stream.write(f"\r{' '*width}\r")

    def write(self, text):
        self.stream.write(text)

    def flush(self):
        self.stream.flush()


class ProgressBar(StatusLine):
    def __init__(self, starting_value=0, max_value=100, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_value = max_value
        self.value = starting_value
        self._last_percent = -1

    def update(self, value, status: Optional[str] = None):
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
            if status:
                s = f"{status} {int(percent * 100.0 + 0.5)}%"
            else:
                s = f"{int(percent * 100.0 + 0.5)}%"
            status_start = (width - len(s)) // 2
            for i in range(width):
                if i == status_start:
                    for j in range(len(s)):
                        if s[j] == ' ' and j + i < pixels:
                            s = s[:j] + '=' + s[j+1:]
                    self.write(s)
                elif status_start < i < status_start + len(s):
                    pass
                elif i < pixels:
                    self.write("=")
                else:
                    self.write("-")
            self.write("]")
            self.flush()


class ProgressBarCallback:
    def __init__(self):
        self.pb = None

    def __call__(self, value, max_value, status: Optional[str] = None):
        if self.pb is None:
            self.pb = ProgressBar(max_value=max_value)
        self.pb.update(value, status)

    def clear(self):
        if self.pb is not None:
            self.pb.clear()
