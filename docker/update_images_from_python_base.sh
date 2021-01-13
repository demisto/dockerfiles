#!/usr/bin/env bash

# exit on errors
set -e

#######################################
# Go over all images and update python base as necessary.
#######################################

## Images which should be updated in a seperate PR (grep regex)
SEPERATE_PR="/pcap-http-extractor/|/office-utils/|/snowflake/|/faker3/"

if [[ -z "$1" ]] || [[ "$1" == -* ]]; then    
    echo "Usage: ${BASH_SOURCE} <python_version (2 or 3)>"
    echo ""
    echo "Update docker images when there are new base docker images available. Create seperate PRs for python 2 and 3 as the build otherwise can time out."
    echo ""
    echo "For example: ${BASH_SOURCE} 2"
    exit 1
fi


if [[ "$1" == "2" ]]; then
    BASE_IMAGES="python python-deb"
elif [[ "$1" == "3" ]]; then
    BASE_IMAGES="python3 python3-deb"
else
    echo "Error: Unknown python version specified: $1"
    exit 2
fi
echo "Starting update of python $1 images using the following base images: $BASE_IMAGES"

# dev only images to ignore
temp_dev=$(mktemp)
grep -l  "devonly=true" docker/*/build.conf | xargs -n 1 dirname > $temp_dev


for image in `echo $BASE_IMAGES` ; do
    full_image="demisto/$image"    
    echo "Processing image: [$full_image]"
    latest_tag=$(./docker/image_latest_tag.py $full_image)
    echo "latest tag: $latest_tag. Updating images..."
    grep -l  -E "FROM\\s+${full_image}:" docker/*/Dockerfile | grep -v -E "$SEPERATE_PR" | grep -v -f $temp_dev | xargs sed -i '' -e "s#${full_image}:.*#${full_image}:${latest_tag}#"
done

rm $temp_dev
