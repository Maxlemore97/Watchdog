"""Shared types used across watchdog_core modules.

Kept in a dedicated module to avoid import cycles between parsers,
fetchers, osv, and analyzer.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Package:
    """An install target as detected by the install-command parser."""

    ecosystem: str
    name: str
    version: str | None


@dataclass
class ArtifactBundle:
    """A curated, size-capped slice of a package or plugin's source files
    plus its metadata. Returned by fetchers, consumed by the analyzer."""

    ecosystem: str
    name: str
    version: str | None
    files: dict
    metadata: dict
    notes: list
