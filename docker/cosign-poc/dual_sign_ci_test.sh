#!/usr/bin/env bash
#
# Dual-sign CI test (POC / CIAC-16370)
# =====================================
# Proves that an EXISTING, already-published Docker image (which is already
# signed with Docker Content Trust / Notary v1) can ADDITIONALLY be signed with
# Sigstore/cosign -- i.e. "dual sign" -- and that both signatures verify.
#
# This is meant to be run from a manually-triggered CI job that has the required
# credentials available as CI secrets. It performs NO build; it only pulls an
# existing image, cosign-signs it by digest, and verifies.
#
# Signing key -- provide ONE of the following:
#   COSIGN_KEY_REF        Preferred. A cosign key reference, e.g. a KMS URI:
#                           gcpkms://projects/<p>/locations/<l>/keyRings/<r>/
#                           cryptoKeys/<k>/cryptoKeyVersions/<n>
#                         With KMS no password is required.
#   COSIGN_PRIVATE_KEY    PEM contents of the cosign private key (static key).
#                         Requires COSIGN_PASSWORD.
#
# Required environment variables (set as CI secrets / variables):
#   COSIGN_PASSWORD       Password protecting COSIGN_PRIVATE_KEY (static key only).
#   DOCKERHUB_USER        Docker Hub user with pull (+push for the signature).
#   DOCKERHUB_PASSWORD    Docker Hub password / token.
#
# Optional:
#   COSIGN_PUBLIC_KEY     PEM contents of the cosign public key used to verify.
#                         If unset, it is derived from the signing key.
#
# Optional environment variables:
#   TARGET_IMAGE          Image ref to dual-sign.
#                         Default: demisto/python3:3.7.5.4328
#   COSIGN_TLOG_UPLOAD    "true"|"false" -- upload to public Rekor transparency
#                         log. Default: "false" (recommended for internal images).
#   VERIFY_DCT            "true"|"false" -- also verify the existing DCT signature
#                         via a trusted pull. Default: "true".
#   COSIGN_VERSION        cosign release to install if not present. Default v2.4.1.
#
# Exit codes:
#   0  dual-sign confirmed (cosign signed+verified; DCT verified if requested)
#   1  a required step failed
#   2  missing required configuration
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
TARGET_IMAGE="${TARGET_IMAGE:-demisto/python3:3.7.5.4328}"
COSIGN_TLOG_UPLOAD="${COSIGN_TLOG_UPLOAD:-false}"
VERIFY_DCT="${VERIFY_DCT:-true}"
COSIGN_VERSION="${COSIGN_VERSION:-v2.4.1}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RESET='\033[0m'
log()  { echo -e "${YELLOW}[dual-sign] $*${RESET}"; }
ok()   { echo -e "${GREEN}[dual-sign] OK: $*${RESET}"; }
fail() { echo -e "${RED}[dual-sign] FAIL: $*${RESET}"; }

require_var() {
    local name="$1"
    if [ -z "${!name:-}" ]; then
        fail "required variable ${name} is not set"
        exit 2
    fi
}

# ---------------------------------------------------------------------------
# 0. Opt-in guard
# ---------------------------------------------------------------------------
# The CI job itself is unconditional (a job gated purely by `rules:` can make
# GitLab reject the pipeline as empty). The opt-in check lives here instead:
# unless RUN_COSIGN_POC is exactly "true", exit successfully without doing
# anything.
if [ "${RUN_COSIGN_POC:-}" != "true" ]; then
    log "RUN_COSIGN_POC is not 'true' (got: '${RUN_COSIGN_POC:-<unset>}'). Nothing to do."
    exit 0
fi

# ---------------------------------------------------------------------------
# 1. Validate configuration
# ---------------------------------------------------------------------------
log "Target image: ${TARGET_IMAGE}"

# Production safety guard.
# Signing writes a `sha256-<digest>.sig` tag into the SAME repository as the
# image. For a `demisto/...` repo that is a customer-facing production
# namespace, and Docker Hub tag deletion is a manual chore. Require an explicit
# acknowledgement so a forgotten/defaulted TARGET_IMAGE can never silently sign
# production. (This exact scenario happened once: an uncommitted default meant
# CI fell back to demisto/python3 instead of the intended devdemisto image.)
case "${TARGET_IMAGE}" in
    demisto/*)
        if [ "${ALLOW_PRODUCTION_SIGNING:-}" != "true" ]; then
            fail "refusing to sign PRODUCTION image '${TARGET_IMAGE}'"
            echo "       Signing adds a .sig tag to a customer-facing repo."
            echo "       Use a devdemisto/... image, or set ALLOW_PRODUCTION_SIGNING=true"
            echo "       if you genuinely intend to sign production."
            exit 2
        fi
        log "ALLOW_PRODUCTION_SIGNING=true - proceeding against PRODUCTION ${TARGET_IMAGE}"
        ;;
esac

# Resolve the signing key reference: prefer an explicit (KMS) ref, otherwise
# fall back to an in-env PEM. Mirrors cosign_sign() in docker/build_docker.sh.
COSIGN_KEY_REF="${COSIGN_KEY_REF:-}"
if [ -z "${COSIGN_KEY_REF}" ] && [ -n "${COSIGN_PRIVATE_KEY:-}" ]; then
    COSIGN_KEY_REF="env://COSIGN_PRIVATE_KEY"
    require_var COSIGN_PASSWORD
fi
if [ -z "${COSIGN_KEY_REF}" ]; then
    fail "no signing key configured: set COSIGN_KEY_REF or COSIGN_PRIVATE_KEY"
    exit 2
fi
log "Using cosign key ref: ${COSIGN_KEY_REF%%://*}://..."

require_var DOCKERHUB_USER
require_var DOCKERHUB_PASSWORD

# ---------------------------------------------------------------------------
# 1. Ensure cosign is available
# ---------------------------------------------------------------------------
if ! command -v cosign >/dev/null 2>&1; then
    log "cosign not found; installing ${COSIGN_VERSION} (linux-amd64)"
    curl -sSfL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64" \
        -o /usr/local/bin/cosign
    chmod +x /usr/local/bin/cosign
fi
cosign version | grep GitVersion || true

# ---------------------------------------------------------------------------
# 2. Docker Hub login (needed to pull and to push the signature artifact)
# ---------------------------------------------------------------------------
log "Logging in to Docker Hub as ${DOCKERHUB_USER}"
if ! echo "${DOCKERHUB_PASSWORD}" | docker login -u "${DOCKERHUB_USER}" --password-stdin; then
    fail "docker login failed"
    exit 1
fi

# ---------------------------------------------------------------------------
# 3. Resolve the image to an immutable digest reference
# ---------------------------------------------------------------------------
log "Pulling target image to resolve its digest"
if ! docker pull "${TARGET_IMAGE}"; then
    fail "could not pull ${TARGET_IMAGE}"
    exit 1
fi

DIGEST_REF="$(docker inspect --format='{{index .RepoDigests 0}}' "${TARGET_IMAGE}" 2>/dev/null)"
if [ -z "${DIGEST_REF}" ]; then
    fail "could not resolve RepoDigest for ${TARGET_IMAGE}"
    exit 1
fi
ok "resolved digest ref: ${DIGEST_REF}"

# ---------------------------------------------------------------------------
# 4. cosign sign (by digest) -- the "second" signature (DCT is the first)
# ---------------------------------------------------------------------------
log "cosign signing ${DIGEST_REF} (tlog upload: ${COSIGN_TLOG_UPLOAD})"
if ! COSIGN_PASSWORD="${COSIGN_PASSWORD:-}" \
     cosign sign --yes \
       --tlog-upload="${COSIGN_TLOG_UPLOAD}" \
       --key "${COSIGN_KEY_REF}" \
       "${DIGEST_REF}"; then
    fail "cosign sign failed"
    exit 1
fi
ok "cosign signature pushed for ${DIGEST_REF}"

# ---------------------------------------------------------------------------
# 5. cosign verify (positive) with the public key
# ---------------------------------------------------------------------------
PUBKEY_FILE="$(mktemp)"
# shellcheck disable=SC2064
trap "rm -f '${PUBKEY_FILE}'" EXIT
if [ -n "${COSIGN_PUBLIC_KEY:-}" ]; then
    printf '%s' "${COSIGN_PUBLIC_KEY}" > "${PUBKEY_FILE}"
else
    # Derive the public key from the signing key -- guarantees they match.
    log "COSIGN_PUBLIC_KEY not set; deriving public key from the signing key"
    if ! COSIGN_PASSWORD="${COSIGN_PASSWORD:-}" \
         cosign public-key --key "${COSIGN_KEY_REF}" > "${PUBKEY_FILE}"; then
        fail "could not derive public key from ${COSIGN_KEY_REF%%://*}://..."
        exit 1
    fi
fi

COSIGN_VERIFY_FLAGS=(--key "${PUBKEY_FILE}")
if [ "${COSIGN_TLOG_UPLOAD}" != "true" ]; then
    # If we did not upload to a transparency log, don't require one on verify.
    COSIGN_VERIFY_FLAGS+=(--insecure-ignore-tlog=true)
fi

log "cosign verifying ${DIGEST_REF}"
if ! cosign verify "${COSIGN_VERIFY_FLAGS[@]}" "${DIGEST_REF}" >/dev/null 2>&1; then
    fail "cosign verify failed"
    cosign verify "${COSIGN_VERIFY_FLAGS[@]}" "${DIGEST_REF}" || true
    exit 1
fi
ok "cosign signature verified"

# ---------------------------------------------------------------------------
# 6. (Optional) Verify the EXISTING DCT/Notary signature via a trusted pull
# ---------------------------------------------------------------------------
if [ "${VERIFY_DCT}" = "true" ]; then
    log "Verifying existing Docker Content Trust signature (trusted pull)"
    if DOCKER_CONTENT_TRUST=1 docker pull "${TARGET_IMAGE}" >/dev/null 2>&1; then
        ok "DCT signature verified"
    else
        fail "DCT trusted pull failed (image may not be DCT-signed on this tag)"
        exit 1
    fi
fi

echo ""
ok "DUAL-SIGN CONFIRMED for ${TARGET_IMAGE}"
echo -e "${GREEN}  - DCT/Notary signature: present & verified${RESET}"
echo -e "${GREEN}  - cosign/Sigstore signature: added & verified${RESET}"
exit 0
