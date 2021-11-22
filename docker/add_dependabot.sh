#!/usr/bin/env bash

# exit on errors
set -e

# Will add the dependabot config of a directory.
# Will add docker and python (if needed) configs

if [[ -z "$1" ]] || [[ "$1" == -* ]]; then    
    echo "Usage: ${BASH_SOURCE} <dir>"
    echo ""
    echo "Add the dependabot config of a directory."
    echo "Will add a docker config and if needed python."
    echo "To add all run: find docker -type d -depth 1 | xargs -n 1 ./docker/add_dependabot.sh"
    echo ""
    echo "For example: ${BASH_SOURCE} docker/ldap"
    exit 1
fi

if [[ ! -d  "$1" ]]; then
    echo "Dir: [$1] specified as command line parameter but directory not found"
    exit 1
fi

SCRIPT_DIR=$(dirname ${BASH_SOURCE})
DEPNDABOT_CONF="${SCRIPT_DIR}/../.github/dependabot.yml"
MODIFIED=0

if [[ $(grep -B 1 -E "directory: /$1"'$' .github/dependabot.yml | grep 'package-ecosystem: pip') ]]; then
    echo "[$1]: Not adding python dependency config as it seems to exist"
else
    if [[ ! -f  "$1/Pipfile" ]]; then
        echo "[$1}: Not adding python dependency config as $1/Pipfile not found"
    else
MODIFIED=1
cat >> $DEPNDABOT_CONF <<- EOM
  - package-ecosystem: pip
    directory: /$1
    schedule: interval: daily
EOM
    fi
fi


if [[ $MODIFIED -eq 1 ]]; then
    echo "[$1]: Done adding dependabot configuration"
fi
