#!/usr/bin/env bash

# exit on errors
set -e

#######################################
# Crypto based images require a special update flow where we update the base image and the dependencies in one go.
#######################################

CYPRTO_TAG=$(./docker/image_latest_tag.py demisto/crypto)

echo "latest crypto image: demisto/crypto:${CYPRTO_TAG}"
# update to latest tag
grep -l  -E 'FROM\s+demisto/crypto' docker/*/Dockerfile  | xargs sed -i '' -e "s#demisto/crypto:.*#demisto/crypto:${CYPRTO_TAG}#"

# update pipenv 
for p in `grep -l -E 'FROM\s+demisto/crypto' docker/*/Dockerfile`; do
    (
        cd $(dirname $p)
        pwd
        echo "updating pipenv ..."
	pipenv --rm || echo "ok that pipenv --rm failed as there could be there there is no env"
        pipenv update
    )
done
