#!/usr/bin/env bash
#
# Standalone cosign signing job (CIAC-16370)
# ==========================================
# Signs images that were ALREADY built and pushed by the dockerfiles build flow, in
# a dedicated CI job that is completely independent of the build/push step and of the
# existing Docker Content Trust (DCT) signing. This lets the legacy DCT sign job be
# deleted later without touching the build.
#
# Input: the list of built/pushed images written by build_docker.sh to
#   ${ARTIFACTS_FOLDER}/built_dockers.txt  (comma-separated "org/image:tag" refs).
#   This is the SAME file the DCT sign job (Tests/docker_files_build/sign_docker.sh)
#   consumes, so cosign signs exactly the images DCT signs.
# For each ref it adds a Sigstore/cosign signature, stored (by digest) in a
# SEPARATE signature repository (NOT co-located with the image). The signature
# repo stays in the SAME org/registry as the image; only the image name is
# prefixed, so the signature lives in a sibling repo:
#   <org>/<image>  ->  <org>/${COSIGN_SIG_PREFIX}<image>
#   e.g. demisto/python3  ->  demisto/sig-python3
# cosign is pointed at that repo via the COSIGN_REPOSITORY env var, keeping the
# `sha256-<digest>.sig` artifacts out of the image repo's tag list.
#
# Signing key (REQUIRED):
#   COSIGN_KEY_REF        A cosign KMS key reference (the ONLY supported key type),
#                         e.g. the URI from cosign/keys.txt:
#                           gcpkms://projects/<p>/locations/<l>/keyRings/<r>/
#                           cryptoKeys/<k>/cryptoKeyVersions/<n>
#                         With KMS no password is required; auth comes from the
#                         runner's GCP credentials. Static PEM keys are NOT
#                         supported.
#
# Registry credentials (needed to push the .sig into the signature repo):
#   DOCKERHUB_USER        Docker Hub user with PUSH rights to the signature repos.
#   DOCKERHUB_PASSWORD    Docker Hub password / access token.
#
# Optional:
#   ARTIFACTS_FOLDER      Where build_docker.sh wrote its artifacts. Default: artifacts.
#   BUILT_DOCKERS_FILE    Explicit path to the built-images list. Default:
#                         ${ARTIFACTS_FOLDER}/built_dockers.txt.
#   BUILT_DOCKERS         Comma-separated refs; overrides the file entirely.
#                         (PUSHED_DOCKERS_FILE / PUSHED_DOCKERS are still honored as
#                         backward-compatible aliases.)
#   COSIGN_SIG_PREFIX     Prefix applied to the image name to form the sibling
#                         signature repo in the SAME org:
#                         <org>/<image> -> <org>/${COSIGN_SIG_PREFIX}<image>.
#                         Default "sig-" (e.g. demisto/python3 -> demisto/sig-python3).
#   COSIGN_TLOG_UPLOAD    "true"|"false" -- upload to the PUBLIC Rekor log. Default "false".
#   COSIGN_VERSION        cosign release to install if absent. Default v2.4.1.
#   DRY_RUN               "true" to report what would be signed without signing.
#
# Exit codes:
#   0  all resolvable images signed (or nothing to do)
#   1  at least one image failed to sign
#   2  missing required configuration
#
set -uo pipefail

readonly DEFAULT_COSIGN_VERSION="v2.4.1"
# Signatures go to a sibling repo in the SAME org, with the image name prefixed
# by this value (demisto/python3 -> demisto/sig-python3).
readonly DEFAULT_COSIGN_SIG_PREFIX="sig-"

ARTIFACTS_FOLDER="${ARTIFACTS_FOLDER:-artifacts}"
COSIGN_SIG_PREFIX="${COSIGN_SIG_PREFIX:-${DEFAULT_COSIGN_SIG_PREFIX}}"
# Read the same list the DCT sign job uses (built_dockers.txt). Accept the legacy
# PUSHED_DOCKERS_FILE as a backward-compatible alias if explicitly set.
BUILT_DOCKERS_FILE="${BUILT_DOCKERS_FILE:-${PUSHED_DOCKERS_FILE:-${ARTIFACTS_FOLDER}/built_dockers.txt}}"
COSIGN_TLOG_UPLOAD="${COSIGN_TLOG_UPLOAD:-false}"
COSIGN_VERSION="${COSIGN_VERSION:-${DEFAULT_COSIGN_VERSION}}"
DRY_RUN="${DRY_RUN:-false}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RESET='\033[0m'
log() { echo -e "${YELLOW}[cosign] $*${RESET}"; }
ok() { echo -e "${GREEN}[cosign] OK: $*${RESET}"; }
fail() { echo -e "${RED}[cosign] FAIL: $*${RESET}"; }

# ---------------------------------------------------------------------------
# 1. Gather the list of images to sign FIRST, so that when nothing was built
#    (the common case) we exit immediately without doing docker login or
#    installing cosign. Mirrors the DCT sign job's early no-op behavior.
# ---------------------------------------------------------------------------
images_csv="${BUILT_DOCKERS:-${PUSHED_DOCKERS:-}}"
if [[ -z "${images_csv}" ]]; then
  if [[ ! -f "${BUILT_DOCKERS_FILE}" ]]; then
    log "no built-images list at ${BUILT_DOCKERS_FILE} and BUILT_DOCKERS is empty. Nothing to sign."
    exit 0
  fi
  images_csv="$(tr -d '\n' <"${BUILT_DOCKERS_FILE}")"
fi
if [[ -z "${images_csv}" ]]; then
  log "built-images list is empty. Nothing to sign."
  exit 0
fi

# Split the comma-separated list into an array.
IFS=',' read -r -a IMAGES <<<"${images_csv}"
log "images to sign: ${#IMAGES[@]}"

# ---------------------------------------------------------------------------
# 2. Resolve the signing key (only reached when there is something to sign).
# ---------------------------------------------------------------------------
COSIGN_KEY_REF="${COSIGN_KEY_REF:-}"
if [[ -z "${COSIGN_KEY_REF}" ]]; then
  fail "COSIGN_KEY_REF is required (the KMS URI from keys.txt). Static PEM keys are not supported."
  exit 2
fi
log "using cosign key ref: ${COSIGN_KEY_REF%%://*}://..."

# ---------------------------------------------------------------------------
# 3. Ensure cosign is available
# ---------------------------------------------------------------------------
if ! command -v cosign >/dev/null 2>&1; then
  log "cosign not found; installing ${COSIGN_VERSION} (linux-amd64)"
  curl -sSfL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64" \
    -o /usr/local/bin/cosign
  chmod +x /usr/local/bin/cosign
fi
cosign version 2>/dev/null | grep GitVersion || true

# Determine the cosign major version so we can pass the correct tlog flags.
# cosign v3 defaults to --use-signing-config=true, which is incompatible with
# --tlog-upload=false; disabling the transparency log there also requires
# --use-signing-config=false. cosign v2 has no --use-signing-config flag.
COSIGN_MAJOR="$(cosign version 2>/dev/null | sed -n 's/^GitVersion:[[:space:]]*v\{0,1\}\([0-9]*\).*/\1/p' | head -n1)"
COSIGN_MAJOR="${COSIGN_MAJOR:-2}"
log "detected cosign major version: ${COSIGN_MAJOR}"

# Build the transparency-log flag set once, based on version.
TLOG_FLAGS=(--tlog-upload="${COSIGN_TLOG_UPLOAD}")
if [[ "${COSIGN_TLOG_UPLOAD}" != "true" && "${COSIGN_MAJOR}" -ge 3 ]]; then
  # v3+: must also opt out of the default signing-config to allow tlog-upload=false.
  TLOG_FLAGS+=(--use-signing-config=false)
fi

# ---------------------------------------------------------------------------
# 4. Docker Hub login (needed to resolve digests and push the .sig)
# ---------------------------------------------------------------------------
if [[ -z "${DOCKERHUB_USER:-}" || -z "${DOCKERHUB_PASSWORD:-}" ]]; then
  fail "DOCKERHUB_USER / DOCKERHUB_PASSWORD are required"
  exit 2
fi
log "logging in to Docker Hub as ${DOCKERHUB_USER}"
if ! echo "${DOCKERHUB_PASSWORD}" | docker login -u "${DOCKERHUB_USER}" --password-stdin; then
  fail "docker login failed"
  exit 1
fi

# ---------------------------------------------------------------------------
# 5. Sign each image by digest, into a SEPARATE per-image signature repo that
#    lives in the SAME org/registry as the image (sibling repo).
#
#    The signature repo keeps the image's registry+org and prefixes the image
#    name with COSIGN_SIG_PREFIX:
#      <org>/<image>[:tag]  ->  <org>/${COSIGN_SIG_PREFIX}<image>
#      e.g. demisto/python3:3.10  ->  demisto/sig-python3
#    cosign is redirected to that repo via COSIGN_REPOSITORY, so the .sig is
#    NOT stored next to the image.
# ---------------------------------------------------------------------------
log "signatures will be stored in sibling repos: <org>/${COSIGN_SIG_PREFIX}<image>"

# Derive the signature repository (COSIGN_REPOSITORY value) for an image ref.
#   demisto/python3:3.10  ->  demisto/sig-python3
# Preserves the registry host and org; only the tag/digest is stripped and the
# image name is prefixed with COSIGN_SIG_PREFIX.
cosign_signature_repo() {
  local ref="$1"
  # Drop tag (":tag") and digest ("@sha256:...") if present.
  ref="${ref%%@*}"
  ref="${ref%:*}"
  # Split into the repo prefix (registry/org) and the final image name.
  local repo_prefix="${ref%/*}"
  local image_name="${ref##*/}"
  if [[ "${repo_prefix}" == "${ref}" ]]; then
    # No slash in the ref (bare image name): no org to preserve.
    echo "${COSIGN_SIG_PREFIX}${image_name}"
  else
    echo "${repo_prefix}/${COSIGN_SIG_PREFIX}${image_name}"
  fi
}

overall_rc=0
for image_ref in "${IMAGES[@]}"; do
  # Trim surrounding whitespace.
  image_ref="${image_ref#"${image_ref%%[![:space:]]*}"}"
  image_ref="${image_ref%"${image_ref##*[![:space:]]}"}"
  [[ -z "${image_ref}" ]] && continue

  sig_repo="$(cosign_signature_repo "${image_ref}")"

  echo ""
  log "=== ${image_ref} ==="
  log "signature stored in separate repo: ${sig_repo}"

  if [[ "${DRY_RUN}" == "true" ]]; then
    log "[DRY-RUN] would cosign-sign ${image_ref} (signature -> ${sig_repo})"
    continue
  fi

  # Resolve to an immutable digest ref (pull is required to inspect RepoDigests).
  if ! docker pull "${image_ref}" >/dev/null 2>&1; then
    fail "could not pull ${image_ref} - skipping"
    overall_rc=1
    continue
  fi
  digest_ref="$(docker inspect --format='{{index .RepoDigests 0}}' "${image_ref}" 2>/dev/null)"
  if [[ -z "${digest_ref}" ]]; then
    fail "could not resolve RepoDigest for ${image_ref} - skipping"
    overall_rc=1
    continue
  fi
  log "digest: ${digest_ref} (tlog upload: ${COSIGN_TLOG_UPLOAD})"

  if COSIGN_REPOSITORY="${sig_repo}" cosign sign --yes \
    "${TLOG_FLAGS[@]}" \
    --key "${COSIGN_KEY_REF}" \
    "${digest_ref}"; then
    ok "signed ${digest_ref} (signature -> ${sig_repo})"
  else
    fail "cosign sign failed for ${digest_ref}"
    overall_rc=1
  fi
done

echo ""
if [[ "${overall_rc}" -eq 0 ]]; then
  ok "cosign signing complete"
else
  fail "cosign signing incomplete - see messages above"
fi
exit "${overall_rc}"
