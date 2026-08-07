"""The hierarchy exists so callers can catch one base class; pin that shape."""

import pytest

from lenticrypt.exceptions import (
    EncodingError,
    InsufficientEntropyError,
    LenticryptError,
    MalformedCiphertextError,
    UnsupportedVersionError,
)

SUBCLASSES = [
    EncodingError,
    InsufficientEntropyError,
    MalformedCiphertextError,
    UnsupportedVersionError,
]


@pytest.mark.parametrize("error_class", SUBCLASSES, ids=[c.__name__ for c in SUBCLASSES])
def test_catchable_as_lenticrypt_error(error_class):
    message = "boom"
    with pytest.raises(LenticryptError):
        raise error_class(message)


def test_unsupported_version_is_a_malformed_ciphertext():
    """A version we cannot read is a special case of "we cannot read this ciphertext"."""
    assert issubclass(UnsupportedVersionError, MalformedCiphertextError)


def test_does_not_shadow_builtin_errors():
    """Callers should still be able to tell a LenticryptError from a programmer error."""
    assert not issubclass(LenticryptError, (ValueError, TypeError))
