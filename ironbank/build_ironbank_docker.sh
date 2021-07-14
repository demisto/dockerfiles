#!/usr/bin/env bash

# exit on errors
set -e

CIRCLE_ARTIFACTS="artifacts"
DIFF_COMPARE=$(cat "$CIRCLE_ARTIFACTS/diff_compare.txt")
SCRIPT_DIR=$(cat "$CIRCLE_ARTIFACTS/script_dir.txt")
CURRENT_DIR=$(cat "$CIRCLE_ARTIFACTS/current_dir.txt")
DOCKER_INCLUDE_GREP=$(cat "$CIRCLE_ARTIFACTS/docker_include_grep.txt")

echo "DIFF_COMPARE: [${DIFF_COMPARE}], SCRIPT_DIR: [${SCRIPT_DIR}], CIRCLE_BRANCH: ${CIRCLE_BRANCH}, PWD: [${CURRENT_DIR}], DOCKER_INCLUDE_GREP: [${DOCKER_INCLUDE_GREP}]"

DIFF_COMPARE="ALL"

SIMPLE_IMAGES="btfl-soup,dempcap,dnspython,ippysocks,jmespath,ldap,netutils,nltk,pandas,python_zipfile,stix2,taxii2,teams,tld,unzip"

function build_ironbank_docker {
  echo "start $1"
  OUTPUT_PATH=ironbank/$(basename $1)
  if [[ ! -d $OUTPUT_PATH ]]; then
    mkdir $OUTPUT_PATH
  fi
  DOCKER_PACKAGES_METADATA_PATH="ironbank/tests/test_data/docker_packages_metadata.txt"
  PYTHONPATH=$CURRENT_DIR python ./ironbank/build_hardening_manifest.py --docker_image_dir $1 --output_path $OUTPUT_PATH --docker_packages_metadata_path $DOCKER_PACKAGES_METADATA_PATH
  echo "done $1"
}

total=$(find $SCRIPT_DIR -maxdepth 1 -mindepth 1 -type  d -print | wc -l)
count=0
for docker_dir in `find $SCRIPT_DIR -maxdepth 1 -mindepth 1 -type  d -print | sort`; do
    if [[ ${DIFF_COMPARE} = "ALL" ]] || [[ $(git diff --name-status $DIFF_COMPARE -- ${docker_dir}) ]]; then
        if [ -n "${DOCKER_INCLUDE_GREP}" ] && [ -z "$(echo ${docker_dir} | grep -E ${DOCKER_INCLUDE_GREP})" ]; then
            [[ -z "$1" ]] && echo "Skipping dir: '${docker_dir}' as not included in grep expression DOCKER_INCLUDE_GREP: '${DOCKER_INCLUDE_GREP}'"
            continue
        fi
        if [ -n "$(echo ${SIMPLE_IMAGES} | grep $(basename ${docker_dir}))" ]; then
          count=$((count+1))
#          echo "=============== `date`: Starting docker build in dir: ${docker_dir} ($count of $total) ==============="
          build_ironbank_docker ${docker_dir}
          cd ${CURRENT_DIR}
#          echo ">>>>>>>>>>>>>>> `date`: Done docker build <<<<<<<<<<<<<"
        fi
    fi
done