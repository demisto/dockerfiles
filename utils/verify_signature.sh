#!/usr/bin/env bash
#
# Verify the cosign signature of a Cortex XSOAR/XSIAM Docker image.
#
# The signature is stored in a sibling repo in the same org, with the image name
# prefixed by "sig-" (e.g. demisto/python3 -> demisto/sig-python3). This script
# derives that repo for you, so you only pass the image reference.
#
# Usage:
#   ./verify_signature.sh <org>/<image>:<tag>
#   ./verify_signature.sh <org>/<image>@sha256:<digest>
#
# Requirements:
#   - cosign on PATH (https://github.com/sigstore/cosign). v2 and v3 both work.
#   - The cosign public key saved as cosign.pub in the current directory
#     (override with PUBLIC_KEY=/path/to/cosign.pub).
#
# Exit codes: 0 verified | 1 usage/environment error | >1 verification failed
set -euo pipefail

readonly PUBLIC_KEY="${PUBLIC_KEY:-cosign.pub}"
readonly SIG_PREFIX="sig-"

image_ref="${1:-}"
if [[ -z "$image_ref" ]]; then
  echo "usage: $0 <org>/<image>:<tag>|@sha256:<digest>" >&2
  exit 1
fi

if ! command -v cosign >/dev/null 2>&1; then
  echo "error: cosign is not installed or not on PATH" >&2
  echo "       install it from https://github.com/sigstore/cosign/releases" >&2
  exit 1
fi

if [[ ! -f "$PUBLIC_KEY" ]]; then
  echo "error: public key '$PUBLIC_KEY' not found" >&2
  echo "       save the cosign public key as cosign.pub, or set PUBLIC_KEY=/path/to/cosign.pub" >&2
  exit 1
fi

# Derive the sibling signature repo: keep the registry+org, prefix the image name.
#   demisto/python3:3.10 -> demisto/sig-python3
signature_repo() {
  local ref="$1"
  ref="${ref%%@*}" # drop @sha256:... digest
  ref="${ref%:*}"  # drop :tag
  local repo_prefix="${ref%/*}"
  local image_name="${ref##*/}"
  if [[ "$repo_prefix" == "$ref" ]]; then
    echo "${SIG_PREFIX}${image_name}"
  else
    echo "${repo_prefix}/${SIG_PREFIX}${image_name}"
  fi
}

repo="$(signature_repo "$image_ref")"
echo "verifying ${image_ref} (signature repo: ${repo})"

COSIGN_REPOSITORY="$repo" cosign verify \
  --key "$PUBLIC_KEY" \
  --insecure-ignore-tlog=true \
  "$image_ref"
