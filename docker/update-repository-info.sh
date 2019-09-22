#!/usr/bin/env bash

# exit on errors
set -e

if [ -z "$CI" ]; then
    echo "This script is meant to be run in CI environment. If you really want to run it set env variable CI=true"
    exit 1
fi

git checkout --track origin/repository-info

echo ""
echo "====== `date`: Starting docker repository update ====="
echo ""

./update-docker-repo-info.py

if [[ $(git status --short) ]]; then
    echo "found modified/new files to commit"
    git status --short
    git add . 
    git commit -m "`date`: automatic docker repository update"
    # git push
fi

echo ""
echo "====== `date`: Done docker repository update ====="
echo ""
