#!/usr/bin/env bash

# exit on errors
set -e

#######################################
# Crypto based images require a special update flow where we update the base image and the dependencies in one go.
#######################################

CYPRTO_TAG=$(./docker/image_latest_tag.py demisto/crypto)

echo "latest crypto image: demisto/crypto:${CYPRTO_TAG}"

# dev only images to ignore
temp_dev=$(mktemp)
grep -l  "devonly=true" docker/*/build.conf | xargs -n 1 dirname > $temp_dev


# update to latest tag
grep -l  -E 'FROM\s+demisto/crypto' docker/*/Dockerfile  | grep -v -f $temp_dev | xargs sed -i '' -e "s#demisto/crypto:.*#demisto/crypto:${CYPRTO_TAG}#"

rm $temp_dev

# update pipenv 
for p in `grep -l -E 'FROM\s+demisto/crypto' docker/*/Dockerfile`; do
    (
        cd $(dirname $p)
        pwd
        echo "updating pipenv ..."
	pipenv --rm || echo "ok that pipenv --rm failed as there could be there is no env"
        pipenv update
    )
done
