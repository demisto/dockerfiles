#!/usr/bin/env bash

# exit on errors
set -e

# Verify that all docker images are properly configured in .github/dependabot.yml file

CURRENT_DIR=`pwd`
SCRIPT_DIR=$(dirname ${BASH_SOURCE})
DOCKER_SRC_DIR=${SCRIPT_DIR}
if [[ "${DOCKER_SRC_DIR}" != /* ]]; then
    DOCKER_SRC_DIR="${CURRENT_DIR}/${SCRIPT_DIR}"
fi
DEPENDABOT_CONFIG="$DOCKER_SRC_DIR/../.github/dependabot.yml"

for d in `find "$DOCKER_SRC_DIR" -maxdepth 1 -mindepth 1 -type d`; do
    echo "Verifying dir: $d"
    name=`basename $d`
    dir=`dirname $d`
    if [[ ! $(grep -E '^devonly=true' $d/build.conf) && ! $(grep -E '^deprecated=true' $d/build.conf) ]]; then # skip devonly and deprecated images
        if [ -f "$d/Pipfile" -o -f "$d/requirements.txt" ]; then
            if [[ ! $(grep -B 1 "/docker/${name}\$" "$DEPENDABOT_CONFIG" | grep "package-ecosystem: pip") ]]; then
                echo "=============================="
                echo "Failed verifying python config for: [$d] in .github/dependabot.yml"
                echo "To add the config run: ./docker/add_dependabot.sh docker/$name"
                exit 2
            fi
        fi
    fi

    # For deprecated images, notify that the image appears in the dependabot config and suggest to add it
    if [[ $(grep -E '^deprecated=true' $d/build.conf) ]]; then
        if [ -f "$d/Pipfile" -o -f "$d/requirements.txt" ]; then
            if [[ $(grep -B 1 "/docker/${name}\$" "$DEPENDABOT_CONFIG" | grep "package-ecosystem: pip") ]]; then
                echo "=============================="
                echo "Foun deprecated image: [$d] in .github/dependabot.yml"
                echo "Consider to remove it so dependabot will not update dependencies"
                exit 2
            fi
        fi
    fi
done
