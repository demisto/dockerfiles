#!/usr/bin/env bash
#
# Dual-sign verification helper (POC / CIAC-16370).
#
# Verifies that a given image carries BOTH:
#   1. A Sigstore/cosign signature (verified with the provided public key), and
#   2. A Docker Content Trust (DCT/Notary v1) signature (verified via docker pull).
#
# Usage:
#   ./verify_dual_sign.sh <image_ref> [cosign_public_key]
#
# Examples:
#   ./verify_dual_sign.sh devdemisto/python3:3.10.14.1234 cosign.pub
#   ./verify_dual_sign.sh us.gcr.io/xsoar-registry/devdemisto/python3:3.10.14.1234 cosign.pub
#
set -euo pipefail

IMAGE_REF="${1:-}"
COSIGN_PUB="${2:-cosign.pub}"

if [ -z "${IMAGE_REF}" ]; then
    echo "Usage: $0 <image_ref> [cosign_public_key]" >&2
    exit 2
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RESET='\033[0m'
overall_rc=0

echo -e "${YELLOW}== Verifying dual signatures for: ${IMAGE_REF} ==${RESET}"

# --- 1. cosign / Sigstore -------------------------------------------------
echo -e "\n${YELLOW}[1/2] cosign (Sigstore) verification${RESET}"
if ! command -v cosign >/dev/null 2>&1; then
    echo -e "${RED}cosign binary not found on PATH.${RESET}"
    overall_rc=1
elif [ ! -f "${COSIGN_PUB}" ]; then
    echo -e "${RED}cosign public key not found: ${COSIGN_PUB}${RESET}"
    overall_rc=1
else
    if cosign verify --key "${COSIGN_PUB}" "${IMAGE_REF}" >/dev/null 2>&1; then
        echo -e "${GREEN}OK: cosign signature is valid.${RESET}"
    else
        echo -e "${RED}FAIL: cosign verification failed.${RESET}"
        # Re-run without suppression to surface the error to the operator.
        cosign verify --key "${COSIGN_PUB}" "${IMAGE_REF}" || true
        overall_rc=1
    fi
fi

# --- 2. Docker Content Trust ---------------------------------------------
echo -e "\n${YELLOW}[2/2] Docker Content Trust (DCT/Notary) verification${RESET}"
if DOCKER_CONTENT_TRUST=1 docker pull "${IMAGE_REF}" >/dev/null 2>&1; then
    echo -e "${GREEN}OK: DCT signature is valid (trusted pull succeeded).${RESET}"
else
    echo -e "${RED}FAIL: DCT trusted pull failed (image may not be DCT-signed).${RESET}"
    overall_rc=1
fi

echo ""
if [ "${overall_rc}" -eq 0 ]; then
    echo -e "${GREEN}== DUAL-SIGN CONFIRMED: both cosign and DCT signatures verified. ==${RESET}"
else
    echo -e "${RED}== DUAL-SIGN NOT CONFIRMED: see failures above. ==${RESET}"
fi
exit "${overall_rc}"
