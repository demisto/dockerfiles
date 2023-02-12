#!/usr/bin/env bash

# exit on errors
set -e

# if native image changes clone content, install sdk like content, run lint

CONTENT_REPO="https://github.com/demisto/content.git"
NATIVE_DEV_IMAGE="native:dev"

# clone content
function clone_content {
  mkdir content
  git clone --depth 1 ${CONTENT_REPO} content
  cd content
  echo "Installing poetry"
  pip install poetry
  echo "Running poetry install"
  poetry install
  echo "Using Poetry version.."
  echo "$(poetry version)"
}

function install_demisto_sdk {
  echo "Found Demisto SDK version in content repo"
  echo "$(poetry show demisto-sdk)"
  # pip3 install demisto-sdk=="${demisto_sdk_version}"
  echo "Running lint"
  demisto-sdk --version
  # demisto-sdk lint --di ${NATIVE_DEV_IMAGE} --target-docker-image "${full_image_name}"
}

CIRCLE_ARTIFACTS="artifacts"
# NATIVE_IMAGE_NAME="py3-native"
NATIVE_IMAGE_NAME="testimage"

native_image_line=$(cat "${CIRCLE_ARTIFACTS}/docker_dirs.txt" | grep "^${NATIVE_IMAGE_NAME}$")

if [[ "${native_image_line}" == "${NATIVE_IMAGE_NAME}" ]]; then
  echo "Found changes in native image ${NATIVE_IMAGE_NAME}. Getting current version."
  full_image_name=$(cat "${CIRCLE_ARTIFACTS}/image_full_name.txt" | grep "${NATIVE_IMAGE_NAME}")
  echo "Found current native image version ${full_image_name}"
  # add tests for multiple names here

  echo "Cloning Content Repo"
  clone_content
  install_demisto_sdk

else
  echo "No changes in native image ${NATIVE_IMAGE_NAME}. Skipping."
fi
