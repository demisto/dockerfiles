#!/usr/bin/env bash

# exit on errors
set -e

BASE_IMAGES=(python python3 python-deb python3-deb)

if [[ -z "$1" ]] || [[ "$1" == -* ]]; then    
    echo "Usage: ${BASH_SOURCE} [packages]"
    echo ""
    echo "Install a common python dependency in all docker python base images."
    echo "Will use pipenv to install the dependency in each directory."
    echo "Base images:"
    for img in ${BASE_IMAGES[*]}
    do
        printf "   %s\n" $img
    done
    echo ""
    echo "For example: ${BASH_SOURCE} dateparser"
    exit 1
fi

current_dir=`pwd`
SCRIPT_DIR=$(dirname ${BASH_SOURCE})

for dir in ${BASE_IMAGES[*]}
do
    echo "===== Installing [$@] in dir: $dir... ====="
    cd "${SCRIPT_DIR}/${dir}"
    #make sure we start with a clean env
    pipenv --rm || echo "Proceeding. It is ok that no virtualenv is available to remove"
    pipenv install "$@"
    cd $current_dir
done
