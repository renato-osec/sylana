"""Exceptions raised by sylana."""

from __future__ import annotations


class SylanaError(Exception):
    """Base class for every sylana error."""


class SylanaToolchainMissing(SylanaError):
    """A required engine binary (normalizer, emitter, clang, klee) is absent."""


class SylanaUnsupported(SylanaError):
    """A requested analysis needs a capability this build does not provide."""


class SylanaUnsupportedCpi(SylanaUnsupported):
    """The program invoked a CPI to a contract sylana does not model."""


class SylanaEngineError(SylanaError):
    """The lift, compile, or symbolic-execution step failed."""
