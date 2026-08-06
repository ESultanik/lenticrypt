import enum
from collections.abc import Hashable, Iterator, Mapping
from typing import Any, Generic, TypeVar

K = TypeVar("K")
# Covariant: a FrozenDict is read-only, so a FrozenDict[str, int] is usable wherever a
# FrozenDict[str, object] is expected.
V_co = TypeVar("V_co", covariant=True)


class CGAColors(enum.Enum):
    BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)


ANSI_RESET = "\033[0m"
ANSI_COLOR = "\033[1;%dm"
ANSI_BOLD = "\033[1m"


class FrozenDict(Mapping[K, V_co], Generic[K, V_co]):
    """An immutable, hashable mapping.

    Written with `TypeVar` + `Generic` rather than PEP 695 `class FrozenDict[K, V]`, because that
    syntax requires Python 3.12 and this package supports 3.10. The two are equivalent to a type
    checker; only the spelling and variance inference differ.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        # As permissive as `dict()` itself, including the keyword form. Built through an explicitly
        # `Any`-typed local: keyword arguments can only ever contribute `str` keys, so inferring
        # directly would widen the key type to `K | str` and contradict the declaration.
        contents: dict[Any, Any] = dict(*args, **kwargs)
        self._mapping: dict[K, V_co] = contents

    def __len__(self) -> int:
        return len(self._mapping)

    def __getitem__(self, key: K) -> V_co:
        return self._mapping[key]

    def __iter__(self) -> Iterator[K]:
        return iter(self._mapping)

    def __str__(self) -> str:
        return str(self._mapping)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self._mapping!r})"

    def __hash__(self) -> int:
        """Hashes over the items, so equal mappings hash equally and unequal ones usually differ.

        The previous version branched on `isinstance(self._mapping, Hashable)` and hashed the dict
        itself -- unreachable, since `dict` sets `__hash__ = None`. The surviving branch hashed only
        the *keys*, so two FrozenDicts with the same keys and different values always collided.
        `Mapping.__eq__` compares values, so hashing them keeps the distribution useful.
        """
        try:
            return hash(frozenset(self._mapping.items()))
        except TypeError:
            # Unhashable values: fall back to the keys. Equal objects still hash equally, which is
            # the requirement; collisions are merely more likely.
            return hash(frozenset(self._mapping))


# `Mapping` sets `__hash__ = None`; defining `__hash__` above restores it. Registering with Hashable
# makes that explicit for `isinstance` checks.
Hashable.register(FrozenDict)
