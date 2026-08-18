#!/usr/bin/env python3
"""
POC helper for CIAC-17423 (per-image parallel build).

Generates a GitLab **child pipeline** YAML with one build job per changed image.
Each generated job runs ``docker/build_docker.sh <image>`` — the existing
single-image build path — so every image builds in its own isolated job. This is
what keeps any single job's disk/artifact footprint small (no whole-batch pile-up).

The list of images is read from a newline-separated file (produced by
``get_changed_images.py --format lines``). If the list is empty, a harmless
no-op job is emitted so the child pipeline is still valid.

Usage:
    python docker/parallel_poc/generate_child_pipeline.py \
        --images-file changed_images.txt \
        --output poc-child-pipeline.yml
"""
from __future__ import annotations

import argparse
from pathlib import Path

# Image the per-image build jobs run in. This POC uses docker-in-docker so
# `build_docker.sh` (which calls `docker buildx`) works inside CI.
BUILD_IMAGE = "docker:24.0"
DIND_SERVICE = "docker:24.0-dind"


def read_images(images_file: Path) -> list[str]:
    """Read newline-separated image names, ignoring blanks/whitespace."""
    if not images_file.is_file():
        return []
    return [
        line.strip()
        for line in images_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _job_name(image: str) -> str:
    """Build a GitLab-safe job name for an image."""
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in image)
    return f"poc-build:{safe}"


def render_pipeline(images: list[str]) -> str:
    """Render the child-pipeline YAML as a string."""
    header = [
        "# AUTO-GENERATED child pipeline for the CIAC-17423 parallel-build POC.",
        "# One job per changed image; each builds a single image in isolation.",
        "",
        "stages:",
        "  - build",
        "",
    ]

    if not images:
        header += [
            "poc-build:noop:",
            "  stage: build",
            "  image: alpine:3.19",
            "  script:",
            '    - echo "No changed images detected — nothing to build."',
            "",
        ]
        return "\n".join(header)

    lines = header
    for image in images:
        lines += [
            f"{_job_name(image)}:",
            "  stage: build",
            f"  image: {BUILD_IMAGE}",
            "  services:",
            f"    - {DIND_SERVICE}",
            "  variables:",
            "    DOCKER_TLS_CERTDIR: \"/certs\"",
            "    # Isolate this job's build artifacts so nothing is shared across jobs.",
            f"    ARTIFACTS_FOLDER: \"artifacts/{image}\"",
            f"    IMAGE_NAME: \"{image}\"",
            "  before_script:",
            "    - apk add --no-cache bash git jq python3 py3-pip >/dev/null",
            "  script:",
            f'    - echo "Building single image: {image}"',
            f'    - mkdir -p "artifacts/{image}"',
            # The existing single-image primitive: build_docker.sh <image>.
            f'    - bash docker/build_docker.sh --save-dir "artifacts/{image}" "{image}"',
            "  artifacts:",
            "    when: always",
            "    paths:",
            f"      - artifacts/{image}/",
            "    expire_in: 1 day",
            "",
        ]
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a GitLab child pipeline with one build job per changed image."
    )
    parser.add_argument(
        "--images-file",
        required=True,
        help="Newline-separated file of image names (from get_changed_images.py --format lines).",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to write the generated child pipeline YAML.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    images = read_images(Path(args.images_file))
    yaml_text = render_pipeline(images)
    Path(args.output).write_text(yaml_text, encoding="utf-8")
    print(f"Wrote child pipeline with {len(images)} build job(s) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
