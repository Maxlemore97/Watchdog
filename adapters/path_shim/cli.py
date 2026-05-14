"""`watchdog-shim` command — install / uninstall / status for the
PATH-prepend wrappers. Installation does not modify the user's shell
config; it prints the PATH line to add and lets the user pick where.
"""
from __future__ import annotations

import argparse
import sys

from .installer import (
    DEFAULT_SHIM_DIR,
    install_shims,
    status,
    uninstall_shims,
)


def _cmd_install(args: argparse.Namespace) -> int:
    written = install_shims(shim_dir=args.dir, overwrite=not args.no_overwrite)
    target = args.dir or str(DEFAULT_SHIM_DIR)
    print(f"Installed {len(written)} shims into {target}")
    for path in written:
        print(f"  {path.name}")
    print()
    print("Add this directory to the FRONT of your PATH:")
    print(f'  export PATH="{target}:$PATH"')
    print("Then restart your shell or `source` your rc file.")
    return 0


def _cmd_uninstall(args: argparse.Namespace) -> int:
    removed = uninstall_shims(shim_dir=args.dir)
    target = args.dir or str(DEFAULT_SHIM_DIR)
    print(f"Removed {len(removed)} shims from {target}")
    for path in removed:
        print(f"  {path.name}")
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    target = args.dir or str(DEFAULT_SHIM_DIR)
    info = status(shim_dir=args.dir)
    print(f"Shim dir: {target}")
    for tool, installed in info.items():
        marker = "ok " if installed else "-- "
        print(f"  {marker} {tool}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="watchdog-shim",
        description="Manage Watchdog PATH-prepend shims for package managers.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_install = sub.add_parser("install", help="Write shim wrappers")
    p_install.add_argument("--dir", help=f"Shim directory (default: {DEFAULT_SHIM_DIR})")
    p_install.add_argument(
        "--no-overwrite",
        action="store_true",
        help="Skip tools that already have a shim",
    )
    p_install.set_defaults(func=_cmd_install)

    p_uninstall = sub.add_parser("uninstall", help="Remove shim wrappers")
    p_uninstall.add_argument("--dir", help=f"Shim directory (default: {DEFAULT_SHIM_DIR})")
    p_uninstall.set_defaults(func=_cmd_uninstall)

    p_status = sub.add_parser("status", help="Show which shims are installed")
    p_status.add_argument("--dir", help=f"Shim directory (default: {DEFAULT_SHIM_DIR})")
    p_status.set_defaults(func=_cmd_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
