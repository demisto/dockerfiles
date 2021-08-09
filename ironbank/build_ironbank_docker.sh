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
    TAG="3.9.6.22912"
    PYTHON_VERSION="3"
    if [[ "$BASE_IMAGE" == "python" ]]; then
      TAG="2.7.18.20958"
      PYTHON_VERSION="2"
    fi
    DOCKER_IMAGE="$REGISTRYONE_URL/ironbank/opensource/palo-alto-networks/demisto/$BASE_IMAGE:$TAG"
    docker pull $DOCKER_IMAGE
    DOCKER_PACKAGES_METADATA_PATH="$OUTPUT_PATH/docker_packages_metadata.txt"
    REQUIREMENTS="$(cat $1/requirements.txt)"
    docker run -it $DOCKER_IMAGE /bin/sh -c "cd ~;dnf install -y --nodocs python$PYTHON_VERSION-devel gcc gcc-c++ make wget git;touch /requirements.txt;echo \"$REQUIREMENTS\" > /requirements.txt;pip uninstall -y -r /requirements.txt;pip cache purge;pip install -v --no-deps --no-cache-dir --log /tmp/pip.log -r /requirements.txt;cat /tmp/pip.log;exit" | grep Added >> $DOCKER_PACKAGES_METADATA_PATH
    python ./ironbank/build_hardening_manifest.py --docker_image_dir $1 --output_path $OUTPUT_PATH --docker_packages_metadata_path $DOCKER_PACKAGES_METADATA_PATH
  else
    echo "Could not login to $REGISTRYONE_URL, aborting..."
    return 1;
  fi
}

# $1: docker image dir (~/../docker/$IMAGE_NAME)
function build_dockerfile {
  OUTPUT_PATH=ironbank/$(basename $1)
  if [[ ! -d $OUTPUT_PATH ]]; then
    mkdir $OUTPUT_PATH
  fi
  python ./ironbank/build_dockerfile.py --docker_image_dir $1 --output_path $OUTPUT_PATH
}

# $1: docker image dir (~/../docker/$IMAGE_NAME)
function build_license {
  IMAGE_NAME=$(basename $1)
  cp LICENSE ironbank/$IMAGE_NAME
}

# $1: docker image dir (~/../docker/$IMAGE_NAME)
function build_readme {
  IMAGE_NAME=$(basename $1)
  echo "Palo Alto Networks - Demisto XSOAR - $IMAGE_NAME image with the required dependencies" > ironbank/$IMAGE_NAME/README.md
}

# $1: docker image dir (~/../docker/$IMAGE_NAME)
function upload_image_to_artifacts {
  IMAGE_NAME=$(basename $1)
  TARGET_PATH="$CIRCLE_ARTIFACTS/$IMAGE_NAME"
  SOURCE_PATH="ironbank/$IMAGE_NAME"
  cp -r $SOURCE_PATH $TARGET_PATH
  cp $CURRENT_DIR/docker/$IMAGE_NAME/requirements.txt $TARGET_PATH
  rm $SOURCE_PATH/docker_packages_metadata.txt
}

# $1: docker image dir (~/../docker/$IMAGE_NAME)
function commit_ironbank_image_to_repo_one {
  IMAGE_NAME=$(basename $1)
  NEW_BRANCH_NAME="$IMAGE_NAME-$CIRCLE_BRANCH"
  if [[ $CIRCLE_BRANCH != 'master' ]]; then
    echo "not running on master, working on a dev branch"
    NEW_BRANCH_NAME="dev-$NEW_BRANCH_NAME"
  fi
  cd ..
  git clone https://$REGISTRYONE_USER:$REGISTRYONE_ACCESS_TOKEN@repo1.dso.mil/dsop/opensource/palo-alto-networks/demisto/$IMAGE_NAME.git
  cd $IMAGE_NAME
  git fetch --all
  git branch
  git checkout development
  if [[ -z $(git checkout -B $NEW_BRANCH_NAME --track origin/$NEW_BRANCH_NAME) ]]; then
    echo "branch $NEW_BRANCH_NAME was not found at origin, creating new branch..."
    git checkout -B $NEW_BRANCH_NAME
  else
    echo "branch $NEW_BRANCH_NAME exists at origin, pulling..."
    git pull
  fi
  cp -r $CURRENT_DIR/ironbank/$IMAGE_NAME/* .
  cp $CURRENT_DIR/docker/$IMAGE_NAME/requirements.txt .
  git config user.email "containers@demisto.com"
  git config user.name "dc-builder"
  if [[ $(git diff --exit-code) ]]; then
    git add -A
    git commit -m "Ironbank auto-generated $IMAGE_NAME image - $CIRCLE_BUILD_NUM"
    git push --set-upstream origin $NEW_BRANCH_NAME
  else
    echo "nothing to commit"
  fi
  cd $CURRENT_DIR
}

# $1: docker image dir (~/../docker/$IMAGE_NAME)
function build_ironbank_docker {
  build_hardening_manifest $1
  build_dockerfile $1
  build_license $1
  build_readme $1
  upload_image_to_artifacts $1
  commit_ironbank_image_to_repo_one $1
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
        if [[ "$(prop 'ironbank' 'false')" == 'true' ]]; then
          cd ${CURRENT_DIR}
          count=$((count+1))
          echo "=============== `date`: Starting ironbank docker build in dir: ${docker_dir} ($count of $total) ==============="
          build_ironbank_docker ${docker_dir}
          IMAGE_NAME=$(basename ${docker_dir})
          if [[ -n "${GENERATES_IMAGES}" ]]; then
            GENERATES_IMAGES="$GENERATES_IMAGES,$IMAGE_NAME"
          else
            GENERATES_IMAGES=$IMAGE_NAME
          fi
          echo ">>>>>>>>>>>>>>> `date`: Done ironbank docker build in dir: ${docker_dir} ($count of $total) <<<<<<<<<<<<<"
        fi
    fi
done

# TODO: think how to infer the exact repo1 build url
python ./ironbank/post_ironbank_github_comment.py --docker_image_dirs $GENERATES_IMAGES 