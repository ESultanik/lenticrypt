"""Exception hierarchy.

Everything raised deliberately by this package derives from `LenticryptError`, so callers -- and the
command line entry point -- can distinguish "your input was bad" from a genuine crash. The package
previously raised bare `Exception`, which forced the CLI to either catch everything or let raw
`struct.error` and `TypeError` tracebacks reach the user.

Programmer errors stay as `ValueError`/`TypeError`: a non-power-of-two nibble-gram length is a
bug in the caller, not malformed data.
"""


class LenticryptError(Exception):
    """Base class for every error this package raises deliberately."""


class EncodingError(LenticryptError):
    """A value could not be encoded, e.g. an integer too large for the variable-width codec."""


class InsufficientEntropyError(LenticryptError):
    """The secrets do not cover the byte combinations needed to encode the plaintexts."""


class MalformedCiphertextError(LenticryptError):
    """The ciphertext is truncated, internally inconsistent, or not a lenticrypt ciphertext."""


class UnsupportedVersionError(MalformedCiphertextError):
    """The ciphertext declares a file format version this build cannot decode."""
