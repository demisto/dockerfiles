#!/usr/bin/env bash

# exit on errors
set -e

BASE_IMAGES=(python python3 python-deb python3-deb)

if [[ "$1" == -* ]]; then    
    echo "Usage: ${BASH_SOURCE}"
    echo ""
    echo "Update all docker python base images to latest available packages."
    echo "Will use pipenv to update the dependencies in each directory."
    echo "Base images:"
    for img in ${BASE_IMAGES[*]}
    do
        printf "   %s\n" $img
    done
    echo ""
    exit 1
fi

current_dir=`pwd`
SCRIPT_DIR=$(dirname ${BASH_SOURCE})

for dir in ${BASE_IMAGES[*]}
do
    echo "===== Updating in dir: $dir... ====="
    cd "${SCRIPT_DIR}/${dir}"
    #make sure we start with a clean env
    pipenv update
    cd $current_dir
done
