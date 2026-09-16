#!/usr/bin/env python3
"""Validate Docker image (directory) names under ``docker/``.

A cosign signature for an image is stored in a sibling repo in the same
org/registry whose name is the image name prefixed by ``sig-`` (the
``COSIGN_SIG_PREFIX`` default), e.g. ``demisto/python3`` ->
``demisto/sig-python3``. If a real image were named ``sig-<something>`` it would
collide with that signature namespace, so new image names must NOT start with
the reserved ``sig-`` prefix.

This script scans the ``docker/`` directory (each sub-directory is an image) and
fails if any image name starts with the reserved prefix.

Exit codes:
  0  all image names are valid
  1  one or more image names use the reserved prefix
"""

from __future__ import annotations

import sys
from pathlib import Path

# Keep in sync with COSIGN_SIG_PREFIX (default "sig-") used by the signing flow.
RESERVED_SIG_PREFIX = "sig-"
DOCKER_DIR = Path(__file__).resolve().parent


def find_reserved_prefixed_images(
    docker_dir: Path, reserved_prefix: str = RESERVED_SIG_PREFIX
) -> list[str]:
    """Return image (sub-directory) names that start with ``reserved_prefix``."""
    if not docker_dir.is_dir():
        return []
    return sorted(
        entry.name
        for entry in docker_dir.iterdir()
        if entry.is_dir() and entry.name.startswith(reserved_prefix)
    )


def main() -> int:
    offenders = find_reserved_prefixed_images(DOCKER_DIR)
    if offenders:
        print(
            f"ERROR: the following Docker image name(s) start with the reserved "
            f"'{RESERVED_SIG_PREFIX}' prefix, which is used for cosign signature "
            f"repositories and must not be used for real images:",
            file=sys.stderr,
        )
        for name in offenders:
            print(f"  - docker/{name}", file=sys.stderr)
        print(
            "Rename the image so it does not start with "
            f"'{RESERVED_SIG_PREFIX}'.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
