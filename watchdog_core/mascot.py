"""ASCII mascot for Watchdog: a parcel propped against a notice board.

Inspired by the dog-on-sign piece at https://asciiart.website/art/4943 (jgs),
with the dog swapped for a package and a banner across the top. The sign body
carries the current event's variable text.

Renders to stderr so it never collides with the JSON hook decision on stdout.
Disable by setting WATCHDOG_MASCOT to one of: 0, false, no, off.
"""
from __future__ import annotations

import os
import sys
from typing import IO, Sequence

EVENT_INTERCEPT = "intercept"
EVENT_PLUGIN_INFO = "plugin_info"
EVENT_PLUGIN_SAFE = "plugin_safe"
EVENT_PLUGIN_UNSAFE = "plugin_unsafe"

_HEADLINES = {
    EVENT_INTERCEPT: "SICHERHEITSCHECK - INTERCEPT",
    EVENT_PLUGIN_INFO: "SICHERHEITSCHECK - PLUGIN INFO",
    EVENT_PLUGIN_SAFE: "SICHERHEITSCHECK - PLUGIN SAFE",
    EVENT_PLUGIN_UNSAFE: "SICHERHEITSCHECK - PLUGIN UNSAFE",
}

BANNER_TEXT = "STOP! SNIFFING FOR PROBLEMS - WATCHDOG ON DUTY"
SIGN_WIDTH = 48


def _enabled() -> bool:
    return os.environ.get("WATCHDOG_MASCOT", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def _wrap(line: str, width: int) -> list[str]:
    line = line.rstrip()
    if len(line) <= width:
        return [line]
    out: list[str] = []
    current = ""
    for word in line.split(" "):
        if not current:
            current = word
        elif len(current) + 1 + len(word) <= width:
            current += " " + word
        else:
            out.append(current)
            current = word
        while len(current) > width:
            out.append(current[:width])
            current = current[width:]
    if current:
        out.append(current)
    return out


def _render_sign(headline: str, lines: Sequence[str], width: int = SIGN_WIDTH) -> list[str]:
    inner = width - 4
    body: list[str] = []
    for raw in lines:
        for piece in _wrap(raw, inner):
            body.append(piece)
    if not body:
        body = [""]

    edge = "+" + "-" * (width - 2) + "+"
    out = [edge]
    out.append("| " + headline.center(inner) + " |")
    out.append(edge)
    for piece in body:
        out.append("| " + piece.ljust(inner) + " |")
    out.append(edge)
    return out


# Default art: dog leaning on a sign. By jgs, https://asciiart.website/art/4943.
_MASCOT_ART = r"""                    __
                  .'  `. /-._
              _.-'/  |  \`-._`-._
 ,        _.-"  ,|  /  a `-. `-._`-._
 |\    .-"       `--""-.__.'=====`-._]
 \ `-'`        .___.--._)============|
  \            .'      |             |
   |     /,_.-'        |             |
 _/   _.'(             |   Package   |
/  ,-' \  \            |             |
\  \    `-'            |             |
 `-'                   '-------------'"""

# Safe-event art: happy dog by hjw, https://asciiart.website/art/7404.
_MASCOT_ART_SAFE_DOG = r""".--.-~-.--.
  \/     \/
   | 9_9 |
   \  Y  /
   /`-U-'\
  |       |
 (\       /)
  \) |_| (/
 (((_| |_)))   """

# Standalone package box (used right of the safe-event dog).
_MASCOT_ART_PACKAGE_BOX = r""" |=============|
 |             |
 |             |
 |   Package   |
 |             |
 |             |
 '-------------'"""

_PACKAGE = _MASCOT_ART.split("\n")
_SAFE_DOG = _MASCOT_ART_SAFE_DOG.split("\n")
_PACKAGE_BOX = _MASCOT_ART_PACKAGE_BOX.split("\n")


def _banner(total_width: int) -> list[str]:
    inner = max(len(BANNER_TEXT) + 4, total_width - 2)
    text = BANNER_TEXT.center(inner)
    border = "+" + "=" * inner + "+"
    return [border, "|" + text + "|", border]


def _compose_default(headline: str, lines: Sequence[str]) -> str:
    sign = _render_sign(headline, lines)
    pkg_width = max(len(r) for r in _PACKAGE)
    gap = "  "

    paw_row = 4  # parcel row that "leans" on the sign top
    body_rows: list[str] = []
    total = max(len(_PACKAGE), paw_row + len(sign))
    for i in range(total):
        left = _PACKAGE[i] if i < len(_PACKAGE) else " " * pkg_width
        if len(left) < pkg_width:
            left = left + " " * (pkg_width - len(left))
        sign_idx = i - paw_row
        right = sign[sign_idx] if 0 <= sign_idx < len(sign) else ""
        body_rows.append((left + gap + right).rstrip() if right else left.rstrip())

    total_width = pkg_width + len(gap) + len(sign[0])
    banner = _banner(total_width)
    return "\n".join(banner + [""] + body_rows)


def _compose_safe(headline: str, lines: Sequence[str]) -> str:
    dog = [d for d in _SAFE_DOG if d != ""] if _SAFE_DOG and _SAFE_DOG[0] == "" else list(_SAFE_DOG)
    box = list(_PACKAGE_BOX)
    dog_w = max(len(r) for r in dog)
    box_w = max(len(r) for r in box)
    gap = "    "

    pad_dog = max(0, (len(box) - len(dog)) // 2)
    pad_box = max(0, (len(dog) - len(box)) // 2)
    n = max(len(dog) + pad_dog, len(box) + pad_box)
    rows: list[str] = []
    for i in range(n):
        d_idx = i - pad_dog
        b_idx = i - pad_box
        left = dog[d_idx] if 0 <= d_idx < len(dog) else ""
        right = box[b_idx] if 0 <= b_idx < len(box) else ""
        rows.append((left.ljust(dog_w) + gap + right).rstrip())

    total_width = dog_w + len(gap) + box_w
    banner = _banner(total_width)
    title = headline.center(total_width)
    out_lines = banner + ["", title, ""] + rows
    if lines:
        out_lines.append("")
        for ln in lines:
            out_lines.append("  " + ln)
    return "\n".join(out_lines)


def _compose(event: str, headline: str, lines: Sequence[str]) -> str:
    if event == EVENT_PLUGIN_SAFE:
        return _compose_safe(headline, lines)
    return _compose_default(headline, lines)


def show(event: str, lines: Sequence[str] | str = (), *, stream: IO[str] | None = None) -> None:
    """Print the mascot for the given event. No-op if disabled."""
    if not _enabled():
        return
    headline = _HEADLINES.get(event, "SICHERHEITSCHECK")
    if isinstance(lines, str):
        body = [lines]
    else:
        body = list(lines)
    out = stream if stream is not None else sys.stderr
    try:
        out.write(_compose(event, headline, body) + "\n")
        out.flush()
    except (OSError, ValueError):
        pass


if __name__ == "__main__":
    ev = sys.argv[1] if len(sys.argv) > 1 else EVENT_INTERCEPT
    demo = {
        EVENT_INTERCEPT: ["Bash install command erkannt", "Pruefung laeuft..."],
        EVENT_PLUGIN_INFO: ["ecosystem: npm", "name: lodash", "version: 4.17.21"],
        EVENT_PLUGIN_SAFE: ["npm:lodash@4.17.21", "Freigegeben - keine Funde."],
        EVENT_PLUGIN_UNSAFE: ["npm:evilpkg@1.0.0", "GHSA-xxxx[critical]"],
    }.get(ev, ["demo"])
    show(ev, demo, stream=sys.stdout)