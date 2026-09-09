#!/usr/bin/env python3
"""
CIAC-17423 - changed-image discovery for the parallel (per-image) dockerfiles build.

Emits the list of docker image directories under ``docker/`` that changed relative
to a base git ref, so the CI pipeline can fan out **one build job per image**. The
per-image build primitive is the existing ``docker/build_docker.sh <image_name>``,
which builds exactly that one image (including its ``requirements.txt`` generation
from Pipfile/pyproject.toml). This script only computes *which* images to build.

Discovery rules (kept in sync with ``build_docker.sh`` PHASE 1 discovery):
  * A directory ``docker/<image>/`` is "changed" if the git diff touches any file
    under it.
  * It is only emitted if it still exists on disk and contains a ``Dockerfile``
    (a deleted image cannot be built).
  * It is skipped if its ``build.conf`` marks it ``deprecated=true`` - deprecated
    images are given special (no-rebuild) handling by the real pipeline, and some
    are unbuildable (e.g. legacy Python 2 images whose committed lock no longer
    resolves). This mirrors the deprecated handling in ``build_docker.sh``.

Output formats:
  * ``json``   (default): a JSON array of image names, e.g. ``["ml", "python3"]``.
  * ``matrix``: a JSON object shaped for a GitLab ``parallel:matrix`` axis, e.g.
    ``{"IMAGE": ["ml", "python3"]}``.
  * ``lines``  : newline-separated image names (handy for shell ``for`` loops).

Usage:
    python docker/dockerfile_matrix/get_changed_images.py --base origin/master
    python docker/dockerfile_matrix/get_changed_images.py \
        --diff-compare "abc123...def456" --format matrix --output images.json
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
# build.conf key/value that marks an image as deprecated (skip it).
DEPRECATED_MARKER = "deprecated=true"


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
    """Return the git repository root (fallback: two levels up from this file)."""
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        return Path(top)
    except (subprocess.CalledProcessError, FileNotFoundError):
        # docker/dockerfile_matrix/ -> repo root is two levels up.
        return Path(__file__).resolve().parents[2]


def is_deprecated(image_dir: Path) -> bool:
    """
    Return True if the image's ``build.conf`` marks it ``deprecated=true``.

    Deprecated images are skipped: the real pipeline does not rebuild them and some
    are unbuildable. Missing build.conf means not deprecated.
    """
    conf = image_dir / "build.conf"
    if not conf.is_file():
        return False
    for line in conf.read_text(encoding="utf-8").splitlines():
        if line.strip().lower() == DEPRECATED_MARKER:
            return True
    return False


def is_buildable(image_dir: Path) -> bool:
    """Return True if the directory exists and contains a Dockerfile."""
    return (image_dir / "Dockerfile").is_file()


def get_changed_image_names(
    diff_compare: str, repo_root: Path | None = None
) -> list[str]:
    """
    Return the sorted, de-duplicated list of buildable, non-deprecated image
    directory names under ``docker/`` that have changes in the given diff range.

    Args:
        diff_compare: A git diff spec, e.g. ``origin/master`` or ``A...B``.
        repo_root: Repository root; auto-detected when omitted.

    Returns:
        Sorted list of image names (the directory name directly under ``docker/``).
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
        if not is_buildable(image_dir):
            continue
        if is_deprecated(image_dir):
            print(f"Skipping deprecated image: {image_name}", file=sys.stderr)
            continue
        images.add(image_name)

    return sorted(images)


def format_output(images: list[str], fmt: str) -> str:
    """Serialize the image list in the requested output format."""
    if fmt == "json":
        return json.dumps(images)
    if fmt == "matrix":
        return json.dumps({MATRIX_VAR: images})
    if fmt == "lines":
        return "\n".join(images)
    if fmt == "dotenv":
        # GitLab dotenv artifact: a single VAR=value line whose value is a JSON
        # array. A downstream job reads it via `dotenv` and expands it as a
        # `parallel:matrix` axis. Example: IMAGES_JSON=["ml", "python3"]
        return f"{MATRIX_VAR}S_JSON={json.dumps(images)}"
    raise ValueError(f"Unknown format: {fmt}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Emit the list of changed, buildable, non-deprecated docker images "
            "for a per-image parallel build matrix."
        )
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
        choices=("json", "matrix", "lines", "dotenv"),
        default="json",
        help="Output format (default: json). 'dotenv' emits "
        "'IMAGES_JSON=[...]' for a GitLab dotenv artifact / matrix axis.",
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

    # Surface the count on stderr for CI logs (does not pollute stdout).
    print(f"Discovered {len(images)} changed image(s): {images}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
