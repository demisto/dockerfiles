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
# For each ref it adds a Sigstore/cosign signature, stored (by digest) in a SEPARATE
# per-image repository derived from the image org:
#   <org>/<image>  ->  <org>-signatures/<image>
# (see cosign_signature_repo; must match docker/build_docker.sh).
#
# Signing key (REQUIRED):
#   COSIGN_KEY_REF        A cosign KMS key reference (the ONLY supported key type),
#                         e.g. the URI from docker/cosign-poc/keys.txt:
#                           gcpkms://projects/<p>/locations/<l>/keyRings/<r>/
#                           cryptoKeys/<k>/cryptoKeyVersions/<n>
#                         With KMS no password is required; auth comes from the
#                         runner's GCP credentials. Static PEM keys are NOT
#                         supported.
#
# Registry credentials (needed to push the .sig into the signature repo):
#   DOCKERHUB_USER        Docker Hub user with PUSH rights to the <org>-signatures repos.
#   DOCKERHUB_PASSWORD    Docker Hub password / access token.
#
# Optional:
#   ARTIFACTS_FOLDER      Where build_docker.sh wrote its artifacts. Default: artifacts.
#   BUILT_DOCKERS_FILE    Explicit path to the built-images list. Default:
#                         ${ARTIFACTS_FOLDER}/built_dockers.txt.
#   BUILT_DOCKERS         Comma-separated refs; overrides the file entirely.
#                         (PUSHED_DOCKERS_FILE / PUSHED_DOCKERS are still honored as
#                         backward-compatible aliases.)
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

ARTIFACTS_FOLDER="${ARTIFACTS_FOLDER:-artifacts}"
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

# Map an image ref to the repository where its cosign signature is stored.
# Must match cosign_signature_repo() in docker/build_docker.sh:
#   [registry/]<org>/<image>[:tag|@digest] -> [registry/]<org>-signatures/<image>
cosign_signature_repo() {
  local ref="$1"
  local repo="${ref%%@*}"
  repo="${repo%:*}"
  local org_path="${repo%/*}"
  local image_name="${repo##*/}"
  local org="${org_path##*/}"
  local prefix="${org_path%/*}"
  local sig_org="${org}-signatures"
  if [[ "${prefix}" == "${org_path}" ]]; then
    echo "${sig_org}/${image_name}"
  else
    echo "${prefix}/${sig_org}/${image_name}"
  fi
}

# ---------------------------------------------------------------------------
# 1. Resolve the signing key
# ---------------------------------------------------------------------------
COSIGN_KEY_REF="${COSIGN_KEY_REF:-}"
if [[ -z "${COSIGN_KEY_REF}" ]]; then
  fail "COSIGN_KEY_REF is required (the KMS URI from keys.txt). Static PEM keys are not supported."
  exit 2
fi
log "using cosign key ref: ${COSIGN_KEY_REF%%://*}://..."

# ---------------------------------------------------------------------------
# 2. Gather the list of images to sign
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
# 3. Ensure cosign is available
# ---------------------------------------------------------------------------
if ! command -v cosign >/dev/null 2>&1; then
  log "cosign not found; installing ${COSIGN_VERSION} (linux-amd64)"
  curl -sSfL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64" \
    -o /usr/local/bin/cosign
  chmod +x /usr/local/bin/cosign
fi
cosign version 2>/dev/null | grep GitVersion || true

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
# 5. Sign each image by digest, into its per-image signature repo
# ---------------------------------------------------------------------------
overall_rc=0
for image_ref in "${IMAGES[@]}"; do
  # Trim surrounding whitespace.
  image_ref="${image_ref#"${image_ref%%[![:space:]]*}"}"
  image_ref="${image_ref%"${image_ref##*[![:space:]]}"}"
  [[ -z "${image_ref}" ]] && continue

  echo ""
  log "=== ${image_ref} ==="
  sig_repo="$(cosign_signature_repo "${image_ref}")"
  log "signature repo: ${sig_repo}"

  if [[ "${DRY_RUN}" == "true" ]]; then
    log "[DRY-RUN] would cosign-sign ${image_ref} -> ${sig_repo}"
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

  if COSIGN_REPOSITORY="${sig_repo}" \
    cosign sign --yes \
    --tlog-upload="${COSIGN_TLOG_UPLOAD}" \
    --key "${COSIGN_KEY_REF}" \
    "${digest_ref}"; then
    ok "signed ${digest_ref} (signature in ${sig_repo})"
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
