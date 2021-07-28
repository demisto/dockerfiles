#!/usr/bin/env bash

# exit on errors
set -e

CIRCLE_ARTIFACTS="artifacts"
DIFF_COMPARE=$(cat "$CIRCLE_ARTIFACTS/diff_compare.txt")
SCRIPT_DIR=$(cat "$CIRCLE_ARTIFACTS/script_dir.txt")
CURRENT_DIR=$(cat "$CIRCLE_ARTIFACTS/current_dir.txt")
DOCKER_INCLUDE_GREP=$(cat "$CIRCLE_ARTIFACTS/docker_include_grep.txt")

echo "DIFF_COMPARE: [${DIFF_COMPARE}], SCRIPT_DIR: [${SCRIPT_DIR}], CIRCLE_BRANCH: ${CIRCLE_BRANCH}, PWD: [${CURRENT_DIR}], DOCKER_INCLUDE_GREP: [${DOCKER_INCLUDE_GREP}]"

# parse a property form build.conf file in current dir
# param $1: property name
# param $2: default value
function prop {
    if [[ ! -e "build.conf" ]]; then
        echo "${2}"
        return 0
    fi
    local RES=$(grep "^${1}=" build.conf | cut -d'=' -f2)
    if [[ "$RES" ]]; then
        echo "$RES"
    else 
        echo "${2}"
    fi
}

REGISTRYONE_URL="registry1.dso.mil"
REGISTRYONE_LOGIN_DONE=no
function registryone_login {
    if [ "${REGISTRYONE_LOGIN_DONE}" = "yes" ]; then
        return 0;
    fi
    if [ -z "${REGISTRYONE_USER}" ]; then
        echo "REGISTRYONE_USER not set. Not logging in to $REGISTRYONE_URL"
        return 1;
    fi
    if [ -z "$REGISTRYONE_PASSWORD" ]; then
        # for local testing scenarios to allow password to be passed via stdin
        docker login -u "${REGISTRYONE_USER}" "${REGISTRYONE_URL}"
    else
        docker login -u "${REGISTRYONE_USER}" -p "${REGISTRYONE_PASSWORD}" "${REGISTRYONE_URL}"
    fi
    if [ $? -ne 0 ]; then
        echo "Failed docker login to $REGISTRYONE_URL"
        exit 3; 
    fi
    REGISTRYONE_LOGIN_DONE=yes
    return 0;
}

# $1: docker image dir (~/../docker/$IMAGE_NAME)
# 1. Login to registry1
# 2. Pull the base image
# 3. Run the base image docker container
# 4. In the container figure out what are the whl/tar.gz/zip files to be downloaded via pip
# 5. Build the hardening_manifest.yaml file
function build_hardening_manifest {
  if registryone_login; then
    OUTPUT_PATH=ironbank/$(basename $1)
    if [[ ! -d $OUTPUT_PATH ]]; then
      mkdir $OUTPUT_PATH
    fi
    BASE_IMAGE=`python ./ironbank/get_docker_image_python_version.py --docker_image_dir $1`
    if [[ "$BASE_IMAGE" == "python" ]]; then
      echo "In the meantime not working with python 2. docker image: $1"
      return 0;
    fi
    DOCKER_IMAGE="$REGISTRYONE_URL/ironbank/opensource/palo-alto-networks/demisto/$BASE_IMAGE:3.9.5.21272"
    docker pull $DOCKER_IMAGE
    DOCKER_PACKAGES_METADATA_PATH="$OUTPUT_PATH/docker_packages_metadata.txt"
    REQUIREMENTS="$(cat $1/requirements.txt | tr "\n" " ")" # replace newline with whitespace
    docker run -it $DOCKER_IMAGE /bin/sh -c "cd ~;pip download -v --no-deps --no-cache-dir --log /tmp/pip.log $REQUIREMENTS;cat /tmp/pip.log | grep Added;exit" >> $DOCKER_PACKAGES_METADATA_PATH
    python ./ironbank/build_hardening_manifest.py --docker_image_dir $1 --output_path $OUTPUT_PATH --docker_packages_metadata_path $DOCKER_PACKAGES_METADATA_PATH
  else
    echo "Could not login to $REGISTRYONE_URL, aborting..."
    return 1;
  fi
}

function build_dockerfile_ironbank {
  OUTPUT_PATH=ironbank/$(basename $1)
  if [[ ! -d $OUTPUT_PATH ]]; then
    mkdir $OUTPUT_PATH
  fi
  python ./ironbank/build_dockerfile.py --docker_image_dir $1 --output_path $OUTPUT_PATH
}

# $1: docker image dir (~/../docker/$IMAGE_NAME)
function build_ironbank_docker {
  build_hardening_manifest $1
  build_dockerfile_ironbak $1
}

total=$(grep -E ironbank=true ./docker/*/build.conf | wc -l)
count=0
for docker_dir in `find $SCRIPT_DIR -maxdepth 1 -mindepth 1 -type  d -print | sort`; do
    if [[ ${DIFF_COMPARE} = "ALL" ]] || [[ $(git diff --name-status $DIFF_COMPARE -- ${docker_dir}) ]]; then
        if [ -n "${DOCKER_INCLUDE_GREP}" ] && [ -z "$(echo ${docker_dir} | grep -E ${DOCKER_INCLUDE_GREP})" ]; then
            [[ -z "$1" ]] && echo "Skipping dir: '${docker_dir}' as not included in grep expression DOCKER_INCLUDE_GREP: '${DOCKER_INCLUDE_GREP}'"
            continue
        fi
        cd ${docker_dir}
#        if [ -n "$(echo ${SIMPLE_IMAGES} | grep $(basename ${docker_dir}))" ]; then
        if [[ "$(prop 'ironbank' 'false')" == 'true' ]]; then
          cd ${CURRENT_DIR}
          count=$((count+1))
          echo "=============== `date`: Starting ironbank docker build in dir: ${docker_dir} ($count of $total) ==============="
          build_ironbank_docker ${docker_dir}
          echo ">>>>>>>>>>>>>>> `date`: Done ironbank docker build in dir: ${docker_dir} ($count of $total) <<<<<<<<<<<<<"
        fi
    fi
done