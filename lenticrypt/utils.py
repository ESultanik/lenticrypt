import enum
from collections.abc import Hashable, Mapping


class CGAColors(enum.Enum):
    BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)


ANSI_RESET = "\033[0m"
ANSI_COLOR = "\033[1;%dm"
ANSI_BOLD = "\033[1m"


class FrozenDict(Hashable, Mapping):
    def __init__(self, *args, **kwargs):
        self._mapping = dict(*args, **kwargs)

    def __len__(self):
        return len(self._mapping)

    def __getitem__(self, key):
        return self._mapping[key]

    def __iter__(self):
        return iter(self._mapping)

    def __str__(self):
        return str(self._mapping)

    def __repr__(self):
        return f"{type(self).__name__}({self._mapping!r})"

    def __hash__(self):
        if isinstance(self._mapping, Hashable):
            return hash(self._mapping)
        else:
            return hash(frozenset(self._mapping.keys()))
