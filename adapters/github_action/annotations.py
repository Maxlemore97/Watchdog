"""GitHub Actions workflow command emitter.

The runner parses lines like

    ::error file=path,line=N,col=M::message

on stdout and turns them into PR file annotations. See:
https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions
"""
from __future__ import annotations

import sys
from typing import IO


def _escape_message(s: str) -> str:
    # GitHub's workflow command parser eats `%`, `\r`, `\n`. Escape them
    # so multi-line analyzer reasons survive the round trip.
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(s: str) -> str:
    # Property values additionally need `,` and `:` escaped.
    return _escape_message(s).replace(",", "%2C").replace(":", "%3A")


def _emit(
    level: str,
    message: str,
    file: str | None = None,
    line: int | None = None,
    col: int | None = None,
    title: str | None = None,
    out: IO[str] | None = None,
) -> None:
    out = out or sys.stdout
    props: list[str] = []
    if file is not None:
        props.append(f"file={_escape_property(file)}")
    if line is not None:
        props.append(f"line={int(line)}")
    if col is not None:
        props.append(f"col={int(col)}")
    if title is not None:
        props.append(f"title={_escape_property(title)}")
    head = f"::{level}"
    if props:
        head += " " + ",".join(props)
    out.write(f"{head}::{_escape_message(message)}\n")


def error(message: str, **kw) -> None:
    _emit("error", message, **kw)


def warning(message: str, **kw) -> None:
    _emit("warning", message, **kw)


def notice(message: str, **kw) -> None:
    _emit("notice", message, **kw)
