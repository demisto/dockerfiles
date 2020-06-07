#!/usr/bin/env bash

# exit on errors
set -e

#######################################
# Go over all images and update python base as necessary.
#######################################

## Images which should be updated in a seperate PR (grep regex)
SEPERATE_PR="/pcap-http-extractor/|/office-utils/|/snowflake/|/faker3/"

# dev only images to ignore
temp_dev=$(mktemp)
grep -l  "devonly=true" docker/*/build.conf | xargs -n 1 dirname > $temp_dev


for image in python python3 python-deb python3-deb ; do
    full_image="demisto/$image"    
    echo "Processing image: [$full_image]"
    latest_tag=$(./docker/image_latest_tag.py $full_image)
    echo "latest tag: $latest_tag. Updating images..."
    grep -l  -E "FROM\\s+${full_image}:" docker/*/Dockerfile | grep -v -E "$SEPERATE_PR" | grep -v -f $temp_dev | xargs sed -i '' -e "s#${full_image}:.*#${full_image}:${latest_tag}#"
done

rm $temp_dev
