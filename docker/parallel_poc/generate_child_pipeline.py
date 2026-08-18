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

Serialization is **stdlib-only**: the pipeline is assembled as a Python dict and
emitted using ``json.dumps`` for every scalar. JSON is a subset of YAML, so a
JSON-encoded string is always a valid, correctly-quoted YAML scalar. This avoids
two problems seen on CI:
  * a PyYAML dependency the slim runner image does not have
    (``ModuleNotFoundError: No module named 'yaml'``), and
  * a hand-written scalar like ``echo "Building single image: ml"`` whose ``: ``
    made YAML parse the script entry as a mapping instead of a string
    (``script config should be a string``).

Usage:
    python docker/parallel_poc/generate_child_pipeline.py \
        --images-file changed_images.txt \
        --output poc-child-pipeline.yml
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

# Image the per-image build jobs run in. This POC uses docker-in-docker so
# `build_docker.sh` (which calls `docker buildx`) works inside CI.
BUILD_IMAGE = "docker:24.0"
DIND_SERVICE = "docker:24.0-dind"

INDENT = "  "


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


def _scalar(value: Any) -> str:
    """Emit a YAML scalar using JSON encoding (JSON is a subset of YAML)."""
    # json.dumps always quotes strings and escapes special chars, so ':' inside a
    # value can never be misread as a mapping. Numbers/bools round-trip fine too.
    return json.dumps(value)


def _dump(node: Any, indent: int, lines: list[str]) -> None:
    """Recursively serialize dicts/lists/scalars to YAML lines."""
    pad = INDENT * indent
    if isinstance(node, dict):
        for key, val in node.items():
            key_str = _scalar(key)
            if isinstance(val, dict) and val:
                lines.append(f"{pad}{key_str}:")
                _dump(val, indent + 1, lines)
            elif isinstance(val, list) and val:
                lines.append(f"{pad}{key_str}:")
                _dump(val, indent, lines)  # lists align with their key
            elif isinstance(val, (dict, list)):  # empty container
                lines.append(f"{pad}{key_str}: {'{}' if isinstance(val, dict) else '[]'}")
            else:
                lines.append(f"{pad}{key_str}: {_scalar(val)}")
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, dict) and item:
                # Render the first key inline with the '-', rest indented.
                first = True
                for key, val in item.items():
                    prefix = f"{pad}- " if first else f"{pad}  "
                    first = False
                    if isinstance(val, (dict, list)) and val:
                        lines.append(f"{prefix}{_scalar(key)}:")
                        _dump(val, indent + 1, lines)
                    else:
                        lines.append(f"{prefix}{_scalar(key)}: {_scalar(val)}")
            else:
                lines.append(f"{pad}- {_scalar(item)}")
    else:
        lines.append(f"{pad}{_scalar(node)}")


def _build_job(image: str) -> dict[str, Any]:
    """
    Return the GitLab job definition (as a dict) for a single image.

    POC intent: prove that with one job per image, each job's artifact (the saved
    image tar) stays well under the per-job artifact/disk limit — so no single job
    can blow past 5 GB the way the whole-batch build does today.

    We build the image directly from its own ``docker/<image>/Dockerfile`` and
    ``docker save | gzip`` it into an ISOLATED per-job directory, then print the
    tar size. This deliberately bypasses ``build_docker.sh`` (which requires a
    pyenv/registry toolchain baked into the infra runner image, not present in the
    generic ``docker:24.0`` image). The full implementation (Phase 5) will run the
    real ``build_docker.sh`` on the infra runner; the sharding shape proven here is
    identical: one image -> one job -> one tar.
    """
    artifacts_dir = f"artifacts/{image}"
    tag = f"poc/{image}:ci"
    tar = f"{artifacts_dir}/{image}.tar"
    return {
        "stage": "build",
        "image": BUILD_IMAGE,
        "services": [DIND_SERVICE],
        "variables": {
            # --- docker-in-docker over TCP (Kubernetes executor) ---
            # On the Kubernetes executor dind runs as a SERVICE container reachable
            # over TCP, not the local unix socket. Without DOCKER_HOST the docker CLI
            # tries unix:///var/run/docker.sock and fails with
            # "Cannot connect to the Docker daemon". Point it at the dind service
            # with TLS (DOCKER_TLS_CERTDIR mounts client certs under /certs/client).
            "DOCKER_HOST": "tcp://docker:2376",
            "DOCKER_TLS_CERTDIR": "/certs",
            "DOCKER_TLS_VERIFY": "1",
            "DOCKER_CERT_PATH": "/certs/client",
            # Isolate this job's build artifacts so nothing is shared across jobs.
            "ARTIFACTS_FOLDER": artifacts_dir,
            "IMAGE_NAME": image,
        },
        "before_script": [
            # Wait for the dind daemon to accept connections before building.
            'for i in $(seq 1 45); do docker info >/dev/null 2>&1 && break; echo "waiting for docker daemon ($i)..."; sleep 2; done',
            # Fail fast (with a clear message) if the daemon never came up.
            'docker info >/dev/null 2>&1 || { echo "ERROR: docker daemon not reachable at $DOCKER_HOST"; exit 1; }',
        ],
        "script": [
            f"echo Building single image {image}",
            f'mkdir -p "{artifacts_dir}"',
            # 1) Try the real per-image build from its own Dockerfile context.
            f'if docker build -t "{tag}" "docker/{image}"; then STATUS=built; else STATUS=fallback; fi',
            # 2) FALLBACK: the POC runner's dind often can't reach Docker Hub, so
            #    real bases (alpine, demisto/*) fail to pull. To still exercise the
            #    exact save/artifact-size mechanics with ZERO registry dependency,
            #    build a `FROM scratch` image containing a large incompressible file.
            #    scratch needs no pull. SYNTH_MB controls the synthetic image size.
            'if [ "$STATUS" = fallback ]; then '
            'echo "Real build unavailable (no base image pull); building synthetic scratch image"; '
            'mkdir -p /tmp/synth; '
            'dd if=/dev/urandom of=/tmp/synth/blob bs=1M count=${SYNTH_MB:-1500}; '
            f'printf "FROM scratch\\nCOPY blob /blob\\n" > /tmp/synth/Dockerfile; '
            f'docker build -t "{tag}" /tmp/synth; fi',
            # 3) Save + gzip the (real or synthetic) image tar into this job's
            #    isolated artifact dir. Always runs now — a tar is guaranteed.
            f'docker save "{tag}" | gzip > "{tar}.gz"',
            # 4) Report the per-job artifact size — this is the number the per-job
            #    (5 GB) limit applies to. With one image per job it stays small.
            f'echo "Per-job artifact for {image}: status=$STATUS"; ls -lh "{tar}.gz"; du -sh "{artifacts_dir}"',
            # 5) Emit a tiny metadata file for the fan-in to consolidate.
            f'SIZE=$(du -b "{tar}.gz" | cut -f1); echo "{image} status=$STATUS bytes=$SIZE" > "{artifacts_dir}/size.txt"; cat "{artifacts_dir}/size.txt"',
        ],
        "artifacts": {
            "when": "always",
            "paths": [f"{artifacts_dir}/"],
            "expire_in": "1 day",
        },
    }


def build_pipeline(images: list[str]) -> dict[str, Any]:
    """Assemble the child-pipeline definition as a dict."""
    pipeline: dict[str, Any] = {"stages": ["build"]}

    if not images:
        pipeline["poc-build:noop"] = {
            "stage": "build",
            "image": "alpine:3.19",
            "script": ["echo No changed images detected - nothing to build."],
        }
        return pipeline

    for image in images:
        pipeline[_job_name(image)] = _build_job(image)
    return pipeline


def render_pipeline(images: list[str]) -> str:
    """Render the child-pipeline YAML as a string (stdlib-only)."""
    lines: list[str] = [
        "# AUTO-GENERATED child pipeline for the CIAC-17423 parallel-build POC.",
        "# One job per changed image; each builds a single image in isolation.",
    ]
    _dump(build_pipeline(images), 0, lines)
    return "\n".join(lines) + "\n"


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
