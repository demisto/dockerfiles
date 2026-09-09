#!/usr/bin/env bash
#
# ONE-TIME signature-repo provisioning (CIAC-16370) -- DELETE AFTER A SINGLE RUN
# =============================================================================
# Creates the Docker Hub repositories that cosign pushes signatures into. cosign
# stores each signature in a SEPARATE per-image repo derived from the image org:
#   <org>/<image>  ->  <org>-signatures/<image>
# (see cosign_signature_repo in cosign_sign_pushed.sh).
#
# When the target <org>-signatures/<image> repo does not exist yet, cosign's
# pre-push manifest check returns:
#   UNAUTHORIZED: authentication required
# because Docker Hub reports a missing org-namespace repo as UNAUTHORIZED rather
# than NOT FOUND. Pre-creating the repos removes that failure.
#
# This script is idempotent: an already-existing repo is treated as success.
#
# Required env:
#   DOCKERHUB_USER      Docker Hub user with rights to create repos in the
#                       target namespaces.
#   DOCKERHUB_PASSWORD  Docker Hub password / access token.
#
# Optional env:
#   SIG_NAMESPACES      Space-separated list of signature namespaces to provision.
#                       Default: "demisto-signatures devdemisto-signatures".
#   SIG_IMAGES          Space-separated list of image names to create under each
#                       namespace. Default: "cosign-test".
#   REPO_PRIVATE        "true"|"false" -- create repos as private. Default "true".
#
# Exit codes:
#   0  all repos exist (created or already present)
#   1  at least one repo could not be created
#   2  missing required configuration
# =============================================================================
set -euo pipefail

readonly HUB_API="https://hub.docker.com/v2"

DOCKERHUB_USER="${DOCKERHUB_USER:-}"
DOCKERHUB_PASSWORD="${DOCKERHUB_PASSWORD:-}"
SIG_NAMESPACES="${SIG_NAMESPACES:-demisto-signatures devdemisto-signatures}"
SIG_IMAGES="${SIG_IMAGES:-cosign-test}"
REPO_PRIVATE="${REPO_PRIVATE:-true}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RESET='\033[0m'
log() { echo -e "${YELLOW}[create-sig-repos] $*${RESET}"; }
ok() { echo -e "${GREEN}[create-sig-repos] OK: $*${RESET}"; }
fail() { echo -e "${RED}[create-sig-repos] FAIL: $*${RESET}"; }

if [[ -z "${DOCKERHUB_USER}" || -z "${DOCKERHUB_PASSWORD}" ]]; then
  fail "DOCKERHUB_USER / DOCKERHUB_PASSWORD are required"
  exit 2
fi

for tool in curl jq; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    fail "required tool '${tool}' not found on PATH"
    exit 2
  fi
done

# ---------------------------------------------------------------------------
# 1. Obtain a Docker Hub JWT (the repo-management API needs a bearer token, not
#    the registry basic-auth used by `docker login`).
# ---------------------------------------------------------------------------
log "authenticating to Docker Hub as ${DOCKERHUB_USER}"
token="$(
  curl -sS -f -X POST "${HUB_API}/users/login" \
    -H "Content-Type: application/json" \
    -d "$(jq -n --arg u "${DOCKERHUB_USER}" --arg p "${DOCKERHUB_PASSWORD}" \
      '{username: $u, password: $p}')" |
    jq -r '.token // empty'
)"
if [[ -z "${token}" ]]; then
  fail "could not obtain Docker Hub API token (check credentials)"
  exit 1
fi
ok "authenticated"

# ---------------------------------------------------------------------------
# 2. Create each repo. POST is idempotent enough for our needs: a 400 with an
#    "already exists" message is treated as success.
# ---------------------------------------------------------------------------
overall_rc=0
for namespace in ${SIG_NAMESPACES}; do
  for image in ${SIG_IMAGES}; do
    log "=== ${namespace}/${image} ==="

    body="$(
      jq -n \
        --arg ns "${namespace}" \
        --arg name "${image}" \
        --argjson priv "$([[ "${REPO_PRIVATE}" == "true" ]] && echo true || echo false)" \
        '{namespace: $ns, name: $name, is_private: $priv, description: "cosign signatures (CIAC-16370)"}'
    )"

    http_code="$(
      curl -sS -o /tmp/create_repo_resp.json -w '%{http_code}' \
        -X POST "${HUB_API}/repositories/" \
        -H "Authorization: JWT ${token}" \
        -H "Content-Type: application/json" \
        -d "${body}"
    )"

    if [[ "${http_code}" == "201" ]]; then
      ok "created ${namespace}/${image}"
    elif grep -qi "already exist" /tmp/create_repo_resp.json 2>/dev/null; then
      ok "${namespace}/${image} already exists"
    else
      fail "could not create ${namespace}/${image} (HTTP ${http_code})"
      sed 's/^/    /' /tmp/create_repo_resp.json 2>/dev/null || true
      overall_rc=1
    fi
  done
done

rm -f /tmp/create_repo_resp.json
echo ""
if [[ "${overall_rc}" -eq 0 ]]; then
  ok "all signature repos provisioned"
else
  fail "one or more signature repos could not be provisioned - see messages above"
fi
exit "${overall_rc}"
