#!/usr/bin/env bash

# exit on errors
set -e

# Verify that all docker images are properly configured in dependabot config.yml file

CURRENT_DIR=`pwd`
SCRIPT_DIR=$(dirname ${BASH_SOURCE})
DOCKER_SRC_DIR=${SCRIPT_DIR}
if [[ "${DOCKER_SRC_DIR}" != /* ]]; then
    DOCKER_SRC_DIR="${CURRENT_DIR}/${SCRIPT_DIR}"
fi
DEPENDABOT_CONFIG="$DOCKER_SRC_DIR/../.dependabot/config.yml"

for d in `find "$DOCKER_SRC_DIR" -maxdepth 1 -mindepth 1 -type d`; do
    echo "Verifying dir: $d"
    name=`basename $d`
    dir=`dirname $d`
    if [[ ! $(grep -E '^devonly=true' $d/build.conf) ]]; then # skip devonly images
        if [[ ! $(grep -B 1 "/docker/${name}\$" "$DEPENDABOT_CONFIG" | grep "package_manager: docker") ]]; then
            echo "=============================="
            echo "Failed verifying docker config for: [$d] in dependabot/.config.yml"
            echo "To add the config run: ./docker/add_dependabot.sh docker/$name"
            exit 1
        fi
        if [ -f "$d/Pipfile" -o -f "$d/requirements.txt" ]; then
            if [[ ! $(grep -B 1 "/docker/${name}\$" "$DEPENDABOT_CONFIG" | grep "package_manager: python") ]]; then
                echo "=============================="
                echo "Failed verifying python config for: [$d] in dependabot/.config.yml"
                echo "To add the config run: ./docker/add_dependabot.sh docker/$name"
                exit 2
            fi
        fi
    fi
done