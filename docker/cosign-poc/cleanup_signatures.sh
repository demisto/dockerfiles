#!/usr/bin/env bash
#
# Cosign signature cleanup (POC / CIAC-16370)
# ===========================================
# Removes the cosign signatures created during the dual-sign POC.
#
# Signatures are stored as a separate `sha256-<digest>.sig` TAG in the same
# repository as the image. Removing one deletes only that tag -- the image
# itself is never touched and normal pulls are unaffected either way.
#
# Deleting a manifest requires DELETE permission on the repository, which is a
# separate grant from push on Docker Hub. Running this from CI is often the only
# way to get it, since the CI robot account may hold rights a personal account
# does not.
#
# Required environment variables:
#   DOCKERHUB_USER        Docker Hub user with DELETE rights on the repos.
#   DOCKERHUB_PASSWORD    Docker Hub password / access token.
#
# Optional:
#   CLEANUP_IMAGES        Space-separated image refs to clean. Defaults to the
#                         two images signed during the POC.
#   COSIGN_VERSION        cosign release to install if absent. Default v2.4.1.
#   DRY_RUN               "true" to report what would be deleted, without
#                         deleting. Default "false".
#
# Exit codes:
#   0  all targeted signatures are gone (or none existed)
#   1  at least one signature could not be removed
#   2  missing required configuration
#
set -uo pipefail

CLEANUP_IMAGES="${CLEANUP_IMAGES:-demisto/python3:3.7.5.4328 devdemisto/python3:3.9.9.25548}"
COSIGN_VERSION="${COSIGN_VERSION:-v2.4.1}"
DRY_RUN="${DRY_RUN:-false}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RESET='\033[0m'
log()  { echo -e "${YELLOW}[cleanup] $*${RESET}"; }
ok()   { echo -e "${GREEN}[cleanup] OK: $*${RESET}"; }
fail() { echo -e "${RED}[cleanup] FAIL: $*${RESET}"; }

for v in DOCKERHUB_USER DOCKERHUB_PASSWORD; do
    if [ -z "${!v:-}" ]; then
        fail "required variable ${v} is not set"
        exit 2
    fi
done

# ---------------------------------------------------------------------------
# 1. Tooling
# ---------------------------------------------------------------------------
if ! command -v cosign >/dev/null 2>&1; then
    log "installing cosign ${COSIGN_VERSION}"
    curl -sSfL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64" \
        -o /usr/local/bin/cosign
    chmod +x /usr/local/bin/cosign
fi
cosign version 2>/dev/null | grep GitVersion || true

log "logging in to Docker Hub as ${DOCKERHUB_USER}"
if ! echo "${DOCKERHUB_PASSWORD}" | docker login -u "${DOCKERHUB_USER}" --password-stdin; then
    fail "docker login failed"
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Helpers
# ---------------------------------------------------------------------------

# Resolve "repo:tag" to its registry digest without pulling the image.
# Falls back to `docker pull` + inspect if the manifest HEAD is unavailable.
resolve_digest() {
    local ref="$1" repo tag token dig
    repo="${ref%:*}"
    tag="${ref##*:}"
    token=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull" \
        | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
    dig=$(curl -s -D- -o /dev/null \
        -H "Authorization: Bearer ${token}" \
        -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
        -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
        -H "Accept: application/vnd.oci.image.index.v1+json" \
        -H "Accept: application/vnd.oci.image.manifest.v1+json" \
        "https://registry-1.docker.io/v2/${repo}/manifests/${tag}" \
        | tr -d '\r' | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: //p')
    if [ -z "${dig}" ]; then
        docker pull "${ref}" >/dev/null 2>&1 || return 1
        dig=$(docker inspect --format='{{index .RepoDigests 0}}' "${ref}" 2>/dev/null | sed 's/.*@//')
    fi
    [ -n "${dig}" ] && echo "${dig}"
}

# Does the .sig tag for this digest still exist?
sig_exists() {
    local repo="$1" digest="$2" token code
    token=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull" \
        | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
    code=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer ${token}" \
        -H "Accept: application/vnd.oci.image.manifest.v1+json" \
        "https://registry-1.docker.io/v2/${repo}/manifests/${digest/:/-}.sig")
    [ "${code}" = "200" ]
}

# Docker Hub does NOT implement the registry-v2 `DELETE /manifests/<ref>` API --
# it answers UNAUTHORIZED ... Action:delete regardless of the account's rights.
# That is why `cosign clean` fails against docker.io even for repo owners.
# The supported path is the Docker Hub *web* API, which needs its own JWT.
HUB_JWT=""
hub_login() {
    [ -n "${HUB_JWT}" ] && return 0
    HUB_JWT=$(curl -s -X POST "https://hub.docker.com/v2/users/login/" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${DOCKERHUB_USER}\",\"password\":\"${DOCKERHUB_PASSWORD}\"}" \
        | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
    [ -n "${HUB_JWT}" ]
}

# Delete a single tag through the Docker Hub API. Echoes the HTTP status.
hub_delete_tag() {
    local repo="$1" tag="$2"
    curl -s -o /dev/null -w "%{http_code}" -X DELETE \
        -H "Authorization: JWT ${HUB_JWT}" \
        "https://hub.docker.com/v2/repositories/${repo}/tags/${tag}/"
}

# ---------------------------------------------------------------------------
# 3. Clean each image
# ---------------------------------------------------------------------------
overall_rc=0

for IMAGE_REF in ${CLEANUP_IMAGES}; do
    echo ""
    log "=== ${IMAGE_REF} ==="
    REPO="${IMAGE_REF%:*}"

    DIGEST="$(resolve_digest "${IMAGE_REF}")"
    if [ -z "${DIGEST}" ]; then
        fail "could not resolve digest for ${IMAGE_REF} - skipping"
        overall_rc=1
        continue
    fi
    log "digest: ${DIGEST}"

    if ! sig_exists "${REPO}" "${DIGEST}"; then
        ok "no cosign signature present - nothing to do"
        continue
    fi
    log "signature tag present: ${DIGEST/:/-}.sig"

    if [ "${DRY_RUN}" = "true" ]; then
        log "[DRY-RUN] would delete ${REPO}:${DIGEST/:/-}.sig"
        continue
    fi

    SIG_TAG="${DIGEST/:/-}.sig"

    # Attempt 1: cosign clean. Works on registries that implement the
    # registry-v2 delete API (GCR/GAR/ECR/Harbor). Expected to fail on
    # Docker Hub; its failure is informational, not fatal.
    log "attempt 1/2: cosign clean"
    cosign clean --force "${REPO}@${DIGEST}" 2>&1 | sed 's/^/    /' || true

    # Attempt 2: Docker Hub web API -- the only delete path docker.io supports.
    if sig_exists "${REPO}" "${DIGEST}"; then
        log "attempt 2/2: Docker Hub tag API"
        if hub_login; then
            HTTP_CODE="$(hub_delete_tag "${REPO}" "${SIG_TAG}")"
            log "DELETE /v2/repositories/${REPO}/tags/${SIG_TAG}/ -> HTTP ${HTTP_CODE}"
        else
            fail "could not obtain a Docker Hub API token for ${DOCKERHUB_USER}"
            echo "       (a Personal Access Token may not be accepted here;"
            echo "        the hub API login often requires the account password)"
        fi
    fi

    if sig_exists "${REPO}" "${DIGEST}"; then
        fail "signature STILL PRESENT for ${IMAGE_REF}"
        echo "       '${DOCKERHUB_USER}' lacks DELETE permission on '${REPO}'"
        echo "       (push and delete are separate grants on Docker Hub)."
        echo "       Delete this tag via the Docker Hub UI with an admin account:"
        echo "         ${REPO}  ->  ${SIG_TAG}"
        overall_rc=1
    else
        ok "signature deleted from ${IMAGE_REF}"
    fi
done

echo ""
if [ "${overall_rc}" -eq 0 ]; then
    ok "cleanup complete - no POC signatures remain"
else
    fail "cleanup incomplete - see messages above"
fi
exit "${overall_rc}"
