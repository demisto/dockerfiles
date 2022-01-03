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
DEPNDABOT_CONF="${SCRIPT_DIR}/../.dependabot/config.yml"
MODIFIED=0

if [[ $(grep -B 1 -E "directory: /$1"'$' .dependabot/config.yml | grep 'package_manager: python') ]]; then
    echo "[$1]: Not adding python dependency config as it seems to exist"
else
    if [[ ! -f  "$1/Pipfile" ]]; then
        echo "[$1}: Not adding python dependency config as $1/Pipfile not found"
    else
MODIFIED=1
cat >> $DEPNDABOT_CONF <<- EOM
  - package_manager: python
    directory: /$1
    update_schedule: live
    automerged_updates:
    - match:
        update_type: semver:minor
EOM
    fi
fi

if [[ $(grep -B 1 -E "directory: /$1"'$' .dependabot/config.yml | grep 'package_manager: docker') ]]; then
    echo "[$1]: Not adding docker dependency config as it seems to exist"
else
    AUTO_MERGE=""
    if [[ $(grep -E '^FROM\s+demisto/' $1/Dockerfile) ]]; then
AUTO_MERGE=$(cat <<-EOM

    automerged_updates:
    - match:
        dependency_name: demisto/*
        update_type: all
EOM
)
    fi
    MODIFIED=1
cat >> $DEPNDABOT_CONF <<- EOM
  - package_manager: docker
    directory: /$1
    update_schedule: daily$AUTO_MERGE

EOM
fi

if [[ $MODIFIED -eq 1 ]]; then
    echo "[$1]: Done adding dependabot configuration"
fi
