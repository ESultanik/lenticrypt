"""FrozenDict: immutability, hashing, and generic parameterisation."""

import pytest

from lenticrypt.utils import FrozenDict

SOURCE = {chr(i): i for i in range(ord("a"), ord("a") + 26)}


@pytest.fixture
def frozen() -> FrozenDict[str, int]:
    return FrozenDict(SOURCE)


def test_compares_equal_to_the_source_mapping(frozen):
    assert frozen == SOURCE
    assert len(frozen) == len(SOURCE)


def test_behaves_as_a_mapping(frozen):
    assert frozen["a"] == SOURCE["a"]
    assert set(frozen) == set(SOURCE)
    assert dict(frozen.items()) == SOURCE
    assert "a" in frozen
    assert "A" not in frozen


def test_item_assignment_is_rejected(frozen):
    with pytest.raises(TypeError):
        frozen["A"] = 1337


def test_is_hashable(frozen):
    assert len(frozenset([frozen, frozen])) == 1


def test_equal_mappings_hash_equally():
    """The requirement that makes it safe as a dict key."""
    assert hash(FrozenDict(SOURCE)) == hash(FrozenDict(dict(SOURCE)))
    assert FrozenDict(SOURCE) == FrozenDict(dict(SOURCE))


def test_hash_distinguishes_differing_values():
    """Hashing only the keys made every same-keyed mapping collide."""
    assert hash(FrozenDict({"a": 1})) != hash(FrozenDict({"a": 2}))


def test_hashable_with_unhashable_values():
    """Values need not be hashable; the fallback keeps equal objects hashing equally."""
    first = FrozenDict({"a": [1, 2]})
    second = FrozenDict({"a": [1, 2]})
    assert hash(first) == hash(second)
    assert first == second


def test_usable_as_a_dict_key(frozen):
    assert {frozen: "value"}[FrozenDict(SOURCE)] == "value"


def test_repr_round_trips_the_type_name(frozen):
    assert repr(frozen).startswith("FrozenDict(")


@pytest.mark.parametrize(
    ("mapping", "key", "expected"),
    [
        ({"a": 1}, "a", 1),
        ({1: "a"}, 1, "a"),
        ({(1, 2): b"x"}, (1, 2), b"x"),
    ],
)
def test_generic_over_key_and_value_types(mapping, key, expected):
    """Parameterisation is checked statically; this pins that it also works at runtime."""
    assert FrozenDict(mapping)[key] == expected


def test_subscripting_the_class_is_allowed():
    """`FrozenDict[str, int]` must be a usable annotation and alias at runtime."""
    alias = FrozenDict[str, int]
    assert alias is not None
    instance: FrozenDict[str, int] = FrozenDict({"a": 1})
    assert instance["a"] == 1
