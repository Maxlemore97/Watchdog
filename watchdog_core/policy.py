"""Verdict aggregation helpers.

The three permission decisions are ordered from least to most restrictive:
allow < ask < deny. Multiple verdicts (e.g. one per package in a chained
install) are combined by taking the worst.
"""
from __future__ import annotations

from typing import Iterable

VERDICT_RANK = {"allow": 0, "ask": 1, "deny": 2}


def rank(verdict: str) -> int:
    return VERDICT_RANK.get(verdict, 1)


def worst_verdict(verdicts: Iterable[str]) -> str:
    best: str | None = None
    for v in verdicts:
        if best is None or rank(v) > rank(best):
            best = v
    return best or "ask"
