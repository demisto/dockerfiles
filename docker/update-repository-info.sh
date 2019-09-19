#!/usr/bin/env bash

# exit on errors
set -e

if [ -z "$CI" ]; then
    echo "This script is meant to be run in CI environment. If you really want to run it set env variable CI=true"
    exit 1
fi

git checkout repository-info

# ./update-docker-repo-info.py

touch test.txt

if [[ $(git status --short) ]]; then
    echo "found modified/new files to commit"
    git status
    # git add . 
    #git commit -m "`date`: automatic docker repository update"
fi

echo "Completed updating docker repo info"
