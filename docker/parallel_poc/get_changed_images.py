#!/usr/bin/env python3
"""
POC helper for CIAC-17423 (per-image parallel build).

Discovers the Docker image directories under ``docker/`` that changed relative to
a base git ref and emits them as a flat list suitable for a GitLab
``parallel:matrix`` axis.

The build step for a single image is already supported by ``docker/build_docker.sh``:
running ``build_docker.sh <image_name>`` builds exactly that one image. This script
produces the list of ``<image_name>`` values, one per matrix job.

Output formats:
  - ``json``   (default): a JSON array of image names, e.g. ``["ml", "python3"]``.
  - ``matrix``: a JSON object shaped for GitLab ``parallel:matrix``, e.g.
    ``{"IMAGE": ["ml", "python3"]}``. Written so it can be consumed as a
    dotenv/artifact by a downstream job.
  - ``lines``  : newline-separated image names (handy for shell ``for`` loops).

Usage:
    python docker/parallel_poc/get_changed_images.py --base origin/master
    python docker/parallel_poc/get_changed_images.py --diff-compare "abc123...def456" --format matrix
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

# Directory (relative to repo root) that holds one sub-directory per docker image.
DOCKER_DIR = "docker"
# Matrix axis variable name the build job will read (build_docker.sh <image>).
MATRIX_VAR = "IMAGE"


def _run_git(args: list[str], repo_root: Path) -> str:
    """Run a git command in ``repo_root`` and return stdout (stripped)."""
    result = subprocess.run(
        ["git", *args],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _repo_root() -> Path:
    """Return the git repository root."""
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        return Path(top)
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fall back to two levels up from this file (docker/parallel_poc/ -> repo root).
        return Path(__file__).resolve().parents[2]


def _is_deprecated(image_dir: Path) -> bool:
    """
    Return True if the image's ``build.conf`` marks it ``deprecated=true``.

    The real pipeline gives deprecated images special (skip/no-rebuild) handling,
    and some are unbuildable (e.g. legacy Python 2 images whose committed lock file
    no longer resolves). We therefore exclude them from the parallel build set, the
    same way the real build does, instead of trying to fix dead images in place.
    """
    conf = image_dir / "build.conf"
    if not conf.is_file():
        return False
    for line in conf.read_text(encoding="utf-8").splitlines():
        if line.strip().lower() == "deprecated=true":
            return True
    return False


def get_changed_image_names(diff_compare: str, repo_root: Path | None = None) -> list[str]:
    """
    Return the sorted, de-duplicated list of image directory names under ``docker/``
    that have changes in the given diff range.

    Args:
        diff_compare: A git diff spec, e.g. ``origin/master`` or ``A...B``.
        repo_root: Repository root; auto-detected when omitted.

    Returns:
        Sorted list of image names (the directory name directly under ``docker/``).
        Only directories that still exist on disk, contain a ``Dockerfile``, and are
        NOT marked ``deprecated=true`` in build.conf are returned (a deleted or
        deprecated image cannot / should not be built).
    """
    root = repo_root or _repo_root()
    changed_files = _run_git(
        ["--no-pager", "diff", "--name-only", diff_compare, "--", DOCKER_DIR],
        root,
    )

    images: set[str] = set()
    for line in changed_files.splitlines():
        parts = Path(line).parts
        # Expect: docker/<image>/<...>. Need at least docker/<image>/<file>.
        if len(parts) < 3 or parts[0] != DOCKER_DIR:
            continue
        image_name = parts[1]
        image_dir = root / DOCKER_DIR / image_name
        # Only include buildable dirs: must exist and contain a Dockerfile.
        if not (image_dir / "Dockerfile").is_file():
            continue
        # Skip deprecated images (mirrors the real pipeline; some are unbuildable).
        if _is_deprecated(image_dir):
            print(f"Skipping deprecated image: {image_name}", file=sys.stderr)
            continue
        images.add(image_name)

    return sorted(images)


def format_output(images: list[str], fmt: str) -> str:
    """Serialize the image list in the requested output format."""
    if fmt == "json":
        return json.dumps(images)
    if fmt == "matrix":
        # GitLab parallel:matrix consumes a list under an axis variable name.
        return json.dumps({MATRIX_VAR: images})
    if fmt == "lines":
        return "\n".join(images)
    raise ValueError(f"Unknown format: {fmt}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Emit the list of changed docker images for a per-image parallel matrix."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--base",
        help="Base git ref to diff against (e.g. origin/master). "
        "Produces a diff spec of '<base>...HEAD'.",
    )
    group.add_argument(
        "--diff-compare",
        help="Explicit git diff spec (e.g. 'A...B' or 'origin/master'). "
        "Overrides --base when provided.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "matrix", "lines"),
        default="json",
        help="Output format (default: json).",
    )
    parser.add_argument(
        "--output",
        help="Optional file to write output to (in addition to stdout).",
    )
    return parser.parse_args(argv)


def resolve_diff_compare(args: argparse.Namespace) -> str:
    """Determine the git diff spec from the provided arguments."""
    if args.diff_compare:
        return args.diff_compare
    if args.base:
        return f"{args.base}...HEAD"
    # Sensible default for a PR/MR pipeline.
    return "origin/master...HEAD"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    diff_compare = resolve_diff_compare(args)

    try:
        images = get_changed_image_names(diff_compare)
    except subprocess.CalledProcessError as exc:
        print(
            f"git diff failed for spec '{diff_compare}': {exc.stderr}",
            file=sys.stderr,
        )
        return 1

    output = format_output(images, args.format)
    print(output)

    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")

    # Also surface the count on stderr for CI logs (does not pollute stdout).
    print(f"Discovered {len(images)} changed image(s): {images}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
