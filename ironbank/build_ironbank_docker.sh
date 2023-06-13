#!/usr/bin/env bash

# exit on errors
set -e

CIRCLE_ARTIFACTS="artifacts"
DIFF_COMPARE=$(cat "$CIRCLE_ARTIFACTS/diff_compare.txt")
SCRIPT_DIR=$(cat "$CIRCLE_ARTIFACTS/script_dir.txt")
CURRENT_DIR=$(cat "$CIRCLE_ARTIFACTS/current_dir.txt")
DOCKER_INCLUDE_GREP=$(cat "$CIRCLE_ARTIFACTS/docker_include_grep.txt")
IMAGE_COMMIT_MAP=()

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
    BASE_IMAGE_NAME_AND_TAG=`python ./ironbank/get_ironbank_base_image_name_and_tag.py --docker_image_dir $1`
    echo "Base image name and tag: $BASE_IMAGE_NAME_AND_TAG"
    PYTHON_VERSION="2"
    if [[ -n $(echo $BASE_IMAGE_NAME_AND_TAG | grep 'python3') ]]; then
      PYTHON_VERSION="3"
    fi
    DOCKER_IMAGE="$REGISTRYONE_URL/$BASE_IMAGE_NAME_AND_TAG"
    echo "Docker image is $DOCKER_IMAGE"
    docker pull $DOCKER_IMAGE
    DOCKER_PACKAGES_METADATA_PATH="$OUTPUT_PATH/docker_packages_metadata.txt"

    if [[ -f  "$1/requirements.txt" ]]; then
      REQUIREMENTS="$(cat $1/requirements.txt)"

      # trim the string output
      REQUIREMENTS="${REQUIREMENTS#"${REQUIREMENTS%%[![:space:]]*}"}"
    fi

    # Run the base image docker container only when requirements.txt exists
    if [[ ! $REQUIREMENTS ]] || [[ $REQUIREMENTS = "-i https://pypi.org/simple" ]]; then
      echo "Skip docker run - requirements.txt file is missing"
    else
      echo "Prepare to Run the image docker container"
      docker run -it $DOCKER_IMAGE /bin/sh -c "cd ~;dnf install -y --nodocs python$PYTHON_VERSION-devel gcc gcc-c++ make wget git;touch /requirements.txt;echo \"$REQUIREMENTS\" > /requirements.txt;pip uninstall -y -r /requirements.txt;pip cache purge;pip install -v --no-deps --no-cache-dir --log /tmp/pip.log -r /requirements.txt;cat /tmp/pip.log;exit" | grep Added >> $DOCKER_PACKAGES_METADATA_PATH
    fi

    echo "Prepare to build hardening_manifest.yaml"
    python ./ironbank/build_hardening_manifest.py --docker_image_dir $1 --output_path $OUTPUT_PATH --docker_packages_metadata_path $DOCKER_PACKAGES_METADATA_PATH
  else
    echo "Could not login to $REGISTRYONE_URL, aborting..."
    return 1;
  fi
}

# $1: docker image dir (~/../docker/$IMAGE_NAME)
function build_dockerfile {
  OUTPUT_PATH=ironbank/$(basename $1)
  DOCKER_PACKAGE_METADATA="$OUTPUT_PATH/docker_packages_metadata.txt"

  if [[ ! -d $OUTPUT_PATH ]]; then
    mkdir $OUTPUT_PATH
  fi
  if [[ -f $1/Dockerfile.ironbank ]]; then
    # if we have a special Dockerfile for ironbank, copy it instead of generating
    echo "$1/Dockerfile.ironbank was found and will use to build the docker"
    cp $1/Dockerfile.ironbank $OUTPUT_PATH/Dockerfile
  # if requirements.txt exists execute build_dockerfile with requirements_file_exists=truw
  elif [[ -f $DOCKER_PACKAGE_METADATA ]]; then
    python ./ironbank/build_dockerfile.py --docker_image_dir $1 --output_path $OUTPUT_PATH --requirements_file_exists true
  else
    python ./ironbank/build_dockerfile.py --docker_image_dir $1 --output_path $OUTPUT_PATH --requirements_file_exists false
    cp $1/Dockerfile.ironbank $OUTPUT_PATH/Dockerfile
  fi
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
  if [[ -f $SOURCE_PATH/docker_packages_metadata.txt ]]; then
    rm $SOURCE_PATH/docker_packages_metadata.txt
  fi

}

# $1: docker image dir (~/../docker/$IMAGE_NAME)
function commit_ironbank_image_to_repo_one {
  IMAGE_NAME=$(basename $1)
  NEW_BRANCH_NAME=$CIRCLE_BRANCH
  if [[ $CIRCLE_BRANCH != 'master' ]]; then
    echo "not running on master, working on a dev branch"
    NEW_BRANCH_NAME="dev-$CIRCLE_BRANCH"
  else
    echo "running on master, repo1 branch is <LATEST_TAG>-feature-branch to avoid conflicting with master"
    DOCKERHUB_IMAGE="demisto/$IMAGE_NAME"
    LATEST_DOCKERHUB_IMAGE_TAG=$(./docker/image_latest_tag.py $DOCKERHUB_IMAGE) # TODO: maybe check for dev image in regular branches
    NEW_BRANCH_NAME="$LATEST_DOCKERHUB_IMAGE_TAG-feature-branch"
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
  sed -i -e '/^-i/d' requirements.txt # remove -i from requirements file
  git config user.email "containers@demisto.com"
  git config user.name "dc-builder"
  if [[ $(git diff --exit-code) ]]; then
    git add -A
    git commit -m "Ironbank generated $IMAGE_NAME image - DF build num: $CIRCLE_BUILD_NUM, DF PR: $CIRCLE_PULL_REQUEST"
    git push --set-upstream origin $NEW_BRANCH_NAME
    IMAGE_COMMIT_MAP+=($IMAGE_NAME=$(git rev-parse HEAD))
    cd $CURRENT_DIR
    if [[ $CIRCLE_BRANCH == 'master' ]]; then
      echo "Opening a Merge Request to Repo1"
      python ./ironbank/open_merge_request.py --access_token $REGISTRYONE_ACCESS_TOKEN --repository $IMAGE_NAME --source_branch $NEW_BRANCH_NAME --target_branch "development" --title "$IMAGE_NAME - $CIRCLE_BRANCH/$CIRCLE_BUILD_NUM"
    fi    
  else
    echo "nothing to commit"
    cd $CURRENT_DIR
  fi
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
          echo ">>>>>>>>>>>>>>> `date`: Done ironbank docker build in dir: ${docker_dir} ($count of $total) <<<<<<<<<<<<<"
        fi
    fi
done

if [[ -n "${IMAGE_COMMIT_MAP}" ]] && [[ $CIRCLE_BRANCH != "master" ]]; then
  # we are not posting on master branch as PR is close, will post to the dockerfiles "Repo1 MR" opened issue instead
  echo "IMAGE_COMMIT_MAP: ${IMAGE_COMMIT_MAP[@]}"
  IMAGE_COMMIT="${IMAGE_COMMIT_MAP[@]}"
  python ./ironbank/post_ironbank_github_comment.py --image_commit_map "$IMAGE_COMMIT" 
fi 