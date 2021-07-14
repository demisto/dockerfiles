#!/usr/bin/env bash

# exit on errors
set -e

echo "hello world"
echo "DOCKER_ORG: ${DOCKER_ORG}, DIFF_COMPARE: [${DIFF_COMPARE}], SCRIPT_DIR: [${SCRIPT_DIR}], CIRCLE_BRANCH: ${CIRCLE_BRANCH}, PWD: [${CURRENT_DIR}]"