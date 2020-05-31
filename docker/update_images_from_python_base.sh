#!/usr/bin/env bash

# exit on errors
set -e

#######################################
# Go over all images and update python base as necessary.
#######################################

for image in python python3 python-deb python3-deb ; do
    full_image="demisto/$image"    
    echo "Processing image: [$full_image]"
    latest_tag=$(./docker/image_latest_tag.py $full_image)
    echo "latest tag: $latest_tag. Updating images..."
    grep -l  -E "FROM\\s+${full_image}:" docker/*/Dockerfile  | xargs sed -i '' -e "s#${full_image}:.*#${full_image}:${latest_tag}#"
done


# update to latest tag
# grep -l  -E 'FROM\s+demisto/crypto' docker/*/Dockerfile  | xargs sed -i '' -e "s#demisto/crypto:.*#demisto/crypto:${CYPRTO_TAG}#"

