#!/usr/bin/env python3

"""Fail-open shim for hook registrations that still use the legacy path."""

from __future__ import annotations

import sys


def main() -> int:
    # Do not parse argv or read stdin. Historical hook registrations must remain
    # inert until every host has removed them and the legacy path can disappear.
    sys.stdout.write("{}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
