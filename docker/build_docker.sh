#!/usr/bin/env bash

# exit on errors
set -e

REVISION=${CI_PIPELINE_ID:-$(date +%s)}
PUSHED_DOCKERS=""
IMAGE_ARTIFACTS=""
CURRENT_DIR=$(pwd)
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
DOCKER_SRC_DIR=${SCRIPT_DIR}
if [[ "${DOCKER_SRC_DIR}" != /* ]]; then
    DOCKER_SRC_DIR="${CURRENT_DIR}/${SCRIPT_DIR}"
fi
DOCKERFILES_TRUST_DIR="$(cd "${DOCKER_SRC_DIR}/.." && pwd)"
DOCKERFILES_TRUST_DIR="${DOCKERFILES_TRUST_DIR}/dockerfiles-trust"

echo "DOCKER_SRC_DIR: ${DOCKER_SRC_DIR}, DOCKERFILES_TRUST_DIR: ${DOCKERFILES_TRUST_DIR}"

# parse a property form build.conf file in current dir
# param $1: property name
# param $2: default value
function prop {
    if [[ ! -e "build.conf" ]]; then
        echo "${2}"
        return 0
    fi
    local RES
    RES=$(grep "^${1}=" build.conf | cut -d'=' -f2)
    if [[ "$RES" ]]; then
        echo "$RES"
    else 
        echo "${2}"
    fi
}

# param $1: filename
# param $2: regex pattern
function get_version_from_file() {
    while IFS= read -r line || [ -n "$line" ]; do
        if [[ $line =~ $2 ]]; then
             version_from_file="${BASH_REMATCH[1]}"
        fi
    done < $1


}

red_error() {
    echo -e "\033[0;31m$1\033[0m"
}

DOCKER_LOGIN_DONE=${DOCKER_LOGIN_DONE:-no}
function docker_login {
    if [ "${DOCKER_LOGIN_DONE}" = "yes" ]; then
        return 0;
    fi
    if [ -z "${DOCKERHUB_USER}" ]; then
        echo "DOCKERHUB_USER not set. Not logging in to docker hub"
        return 1;
    fi
    if [ -z "$DOCKERHUB_PASSWORD" ]; then
        #for local testing scenarios to allow password to be passed via stdin
        docker login -u "${DOCKERHUB_USER}" 
    else
        docker login -u "${DOCKERHUB_USER}" -p "${DOCKERHUB_PASSWORD}" 
    fi
    if [ $? -ne 0 ]; then
        echo "Failed docker login for user: ${DOCKERHUB_USER}"
        return 2; 
    fi
    DOCKER_LOGIN_DONE=yes
    return 0;
}

CR_LOGIN_DONE=no
function cr_login {
    if [ "${CR_LOGIN_DONE}" = "yes" ]; then
        return 0;
    fi
    if [ -z "${CR_USER}" ]; then
        echo "CR_USER not set. Not logging in to container registry"
        return 1;
    fi
    cr_url="https://$(echo ${CR_REPO} | cut -d / -f 1)"
    if [ -z "$CR_PASSWORD" ]; then
        #for local testing scenarios to allow password to be passed via stdin
        docker login -u "${CR_USER}" ${cr_url}
    else
        docker login -u "${CR_USER}" -p "${CR_PASSWORD}" ${cr_url}
    fi
    if [ $? -ne 0 ]; then
        echo "Failed docker login to CR repo"
        exit 3; 
    fi
    CR_LOGIN_DONE=yes
    return 0;
}

SIGN_SETUP_DONE=no
DOCKERFILES_TRUST_GIT_URL=""
function sign_setup {
    if [ "${SIGN_SETUP_DONE}" = "yes" ]; then
        return 0;
    fi
    if [ -z "${DOCKER_CONTENT_TRUST_REPOSITORY_PASSPHRASE}" ] || [ -z "${DOCKER_CONTENT_TRUST_ROOT_PASSPHRASE}" ] || [ -z "${DOCKERFILES_TRUST_GIT_HTTPS}" ]; then
        echo "Content trust passphrases not set. Not setting up docker signing."
        return 1;
    fi
    DOCKERFILES_TRUST_GIT_URL="https://oauth2:${GITHUB_TOKEN}@${DOCKERFILES_TRUST_GIT_HTTPS}"

    if [ ! -d "${DOCKERFILES_TRUST_DIR}" ]; then
        git clone "${DOCKERFILES_TRUST_GIT_URL}" "${DOCKERFILES_TRUST_DIR}"
        git remote set-url origin "${DOCKERFILES_TRUST_GIT_URL}"
        git config --file "${DOCKERFILES_TRUST_DIR}/.git/config"  user.email "dc-builder@users.noreply.github.com"
        git config --file "${DOCKERFILES_TRUST_DIR}/.git/config" user.name "dc-builder"           
    else
        echo "${DOCKERFILES_TRUST_DIR} already checked out"
    fi
    export DOCKER_CONFIG="${DOCKERFILES_TRUST_DIR}/.docker"
    SIGN_SETUP_DONE=yes
    return 0;
}

function commit_dockerfiles_trust {
    cwd="$PWD"
    cd "${DOCKERFILES_TRUST_DIR}"
    if [[ $(git status --short) ]]; then
        echo "dockerfiles-trust: found modified/new files to commit"
        git stash
        git pull --no-rebase
        git stash list | grep -q 'stash' && git checkout stash -- .
        git add -A
        echo "starting commit loop..."
        git commit -m "$(date): trust update from PR: ${CI_COMMIT_REF_NAME} commit: ${CI_COMMIT_SHA}"
        COMMIT_DONE=no
        for i in 1 2 3 4 5; do
            echo "Attempt $i to push..."
            if git push --set-upstream "${DOCKERFILES_TRUST_GIT_URL}"; then
                echo "Push done successfully"
                COMMIT_DONE=yes
                break;
            else
                echo "Push failed. Trying pull and then another..."
                sleep $(((RANDOM % 10) + 1))
                git pull --rebase
            fi
        done
        if [ "${COMMIT_DONE}" = "no" ]; then
            echo "Failed committing trust data"
            exit 5
        fi
    else
        echo "dockerfiles-trust: no changed files. nothing to commit and push"
    fi
    cd "$cwd"
}

# build docker. 
# Param $1: docker dir with all relevant files
function docker_build {
    DOCKER_ORG=${DOCKER_ORG:-devdemisto}
    DOCKER_ORG_DEMISTO=demisto
    image_name=$(basename $1)
    echo "Starting build for dir: $1, image: ${image_name}, pwd: $(pwd)"
    cd $1        
    if  [[ "${CI_COMMIT_REF_NAME}" == "master" ]] && [[ "$(prop 'devonly')" ]]; then
        echo "== skipping image [${image_name}] as it is marked devonly =="
        return 0
    fi
    
    VERSION=$(prop 'version' '1.0.0')    
    VERSION="${VERSION}.${REVISION}"
    echo "${image_name}: using version: ${VERSION}"
    image_full_name="${DOCKER_ORG}/${image_name}:${VERSION}"

    if [[ "$(prop 'deprecated')" ]]; then
        echo "${DOCKER_ORG_DEMISTO}/${image_name} image is deprecated, checking whether the image is listed in the deprecated list or not"
        reason=$(prop 'deprecated_reason')        
        ${PY3CMD} "${DOCKER_SRC_DIR}"/add_image_to_deprecated_or_internal_list.py "${DOCKER_ORG_DEMISTO}"/"${image_name}" "${reason}" "${DOCKER_SRC_DIR}"/deprecated_images.json
    fi

    del_requirements=no
    if [ -f "Pipfile" ] && [ ! -f "requirements.txt" ]; then
        if [ ! -f "Pipfile.lock" ]; then
            echo "Error: Pipfile present without Pipfile.lock. Make sure to commit your Pipfile.lock file"
            return 1
        fi

        if [[ "$(prop 'dont_generate_requirements')" ]]; then
          echo 'Not generating requirements as dont_generate_requirements is true' # only implemented for pipenv
        else
          pipenv --rm || echo "Proceeding. It is ok that no virtualenv is available to remove"
          pipenv install --deploy # fails if lock is outdated
          PIPENV_YES=yes pipenv run pip freeze > requirements.txt
          echo "Pipfile lock generated requirements.txt: "
          echo "############ REQUIREMENTS.TXT ############"
          cat requirements.txt
          echo "##########################################"
          [ ! -f requirements.txt ] && echo "WARNING: requirements.txt does not exist, this is ok if python usage is not intended."
          [ ! -s requirements.txt ] && echo "WARNING: requirements.txt is empty"
          # del_requirements=yes
        fi

    fi

    if [ -f "pyproject.toml" ] && [ ! -f "requirements.txt" ]; then
       if [ ! -f "poetry.lock" ]; then
            echo "Error: pyproject.toml present without poetry.lock. Make sure to commit your poetry.lock file"
            return 1
        fi

      echo "starting to install dependencies from poetry..."
      poetry --version
      poetry export -f requirements.txt --output requirements.txt --without-hashes
      echo "poetry.lock generated requirements.txt file: "
      echo "############ REQUIREMENTS.TXT ############"
      cat requirements.txt
      echo "##########################################"

    fi

    tmp_dir=$(mktemp -d)
    cp Dockerfile "$tmp_dir/Dockerfile"
    echo "" >> "$tmp_dir/Dockerfile"
    echo "ENV DOCKER_IMAGE=$image_full_name" >> "$tmp_dir/Dockerfile"
    
    if [[ "$(prop 'deprecated')" ]]; then
        echo "ENV DEPRECATED_IMAGE=true" >> "$tmp_dir/Dockerfile"
        reason=$(prop 'deprecated_reason')
        echo "ENV DEPRECATED_REASON=\"$reason\"" >> "$tmp_dir/Dockerfile"
    fi

    echo "### DOCKER LOGIN START ###"
    docker_login
    echo "### DOCKER LOGIN DONE ###"

    docker buildx build -f "$tmp_dir/Dockerfile" . -t ${image_full_name} \
        --label "org.opencontainers.image.authors=Demisto <containers@demisto.com>" \
        --label "org.opencontainers.image.version=${VERSION}" \
        --label "org.opencontainers.image.revision=${CI_COMMIT_SHA}"

    if [[ -e "dynamic_version.sh" ]]; then
      echo "dynamic_version.sh file was found"
      dynamic_version=$(docker run --rm -i "$image_full_name" sh < dynamic_version.sh)
      echo "dynamic_version $dynamic_version"
      VERSION="${dynamic_version}.${REVISION}"
      image_full_name="${DOCKER_ORG}/${image_name}:${VERSION}"

      # add the last layer and rebuild. Everything should be cached besides this layer
      echo "ENV DOCKER_IMAGE=$image_full_name" >> "$tmp_dir/Dockerfile"

      echo "running docker build again with tag $image_full_name"

      docker buildx build -f "$tmp_dir/Dockerfile" . -t ${image_full_name} \
        --label "org.opencontainers.image.authors=Demisto <containers@demisto.com>" \
        --label "org.opencontainers.image.version=${VERSION}" \
        --label "org.opencontainers.image.revision=${CI_COMMIT_SHA}"
    fi
    rm -rf "$tmp_dir"

    if [ ${del_requirements} = "yes" ]; then
        rm requirements.txt
    fi
    if [ -n "${GITLAB_CI}" ]; then
        echo "Checking that source files were not modified by build..."
        DIFF_OUT=$(git diff -- .)
        if [[ -n "$DIFF_OUT" ]]; then
            echo "Found modified files. Failing the build!!"
            echo "git diff -- . output:"
            echo "$DIFF_OUT"
            if [[ $DIFF_OUT == *"Pipfile.lock"* ]]; then
                echo "Seems that Pipfile.lock was modified by the build. Make sure you updated and committed the Pipfile.lock file."
                echo "To resolve this run: 'pipenv lock --keep-outdated'"
                echo "Or if you want to update dependencies run without '--keep-outdated'"
                echo "Then commit the Pipfile.lock file."
            fi
            echo "FAILED: $image_name"
            return 1
        fi
    fi

    echo "================= $(date): Starting version verification on image: ${image_name} ================="
    echo "Checking that the image python version match with the Pipfile/pyproject.toml python version..."
    # Get the python version from the docker metadata.
    PYTHON_VERSION=$(docker inspect "$image_full_name" | jq -r '.[].Config.Env[]|select(match("^PYTHON_VERSION"))|.[index("=")+1:]')
    PY3CMD="python3"
    if [ -f "Pipfile" ]; then
        file_name="Pipfile"
        get_version_from_file 'Pipfile' 'python_version = \"([^\"]+)\"'
    fi
    if [ -f "pyproject.toml" ]; then 
        file_name="pyproject.toml"
        get_version_from_file 'pyproject.toml' '^python = \"([^\"]+)\"'
    fi
    if [ -f "Pipfile" ] || [ -f "pyproject.toml" ]; then
        set +e
        output=$($PY3CMD "${DOCKER_SRC_DIR}"/verify_version_matching.py "${PYTHON_VERSION}" "${version_from_file}" "${image_name}" "${file_name}")
        if [ $? -ne 0 ]; then
            errors+=("$output")
        fi
        set -e
    fi

    
    if [[ "$(prop 'devonly')" ]]; then
        echo "Skipping license verification for devonly image"
    else
        PY3CMD="python3"
        $PY3CMD ${DOCKER_SRC_DIR}/verify_licenses.py ${image_full_name}
    fi
    local filename
    while IFS= read -r -d '' filename; do
        echo "==========================="
        echo "Verifying docker image by running the python script $filename within the docker image"
        cat "${filename}" | docker run --rm -i ${image_full_name} python '-'
    done < <(find . -name "*verify.py" -print0)

    if [ -f "verify.ps1" ]; then
        echo "==========================="            
        echo "Verifying docker image by running the pwsh script verify.ps1 within the docker image"
        # use "tee" as powershell doesn't fail on throw when run with -c
        cat verify.ps1 | docker run --rm -i ${image_full_name} sh -c 'tee > verify.ps1; pwsh verify.ps1'
    fi
    docker_trust=0
    if sign_setup; then
        docker_trust=1
        echo "using DOCKER_TRUST=${docker_trust} DOCKER_CONFIG=${DOCKER_CONFIG}"
    fi

    if [ -n "$CR_REPO" ] && cr_login; then
        docker tag ${image_full_name} ${CR_REPO}/${image_full_name}
        docker push ${CR_REPO}/${image_full_name} > /dev/null
        echo "Done docker push for cr: ${image_full_name}"
    else
        echo "Skipping docker push for cr"
    fi

    DOCKER_LOGIN_DONE="no"
    if docker_login; then
        echo "Done docker login"
        env DOCKER_CONTENT_TRUST=$docker_trust DOCKER_CONFIG="${DOCKER_CONFIG}"  docker push ${image_full_name}
        echo "Done docker push for: ${image_full_name}"
        PUSHED_DOCKERS="${image_full_name},$PUSHED_DOCKERS"
        echo "debug pushed_dockers $PUSHED_DOCKERS"
        if [[ "$docker_trust" == "1" ]]; then
            commit_dockerfiles_trust
        fi
        if ! "${DOCKER_SRC_DIR}/post_github_comment.py" "${image_full_name}"; then
            echo "Failed post_github_comment.py. Will stop build only if not on master"
            if [ "${CI_COMMIT_REF_NAME}" == "master" ]; then
                echo "Continuing as we are on master branch..."
            else
                echo "failing build!!"
                exit 5
            fi
        fi
    else
        echo "Skipping docker push"
        if [ "${CI_COMMIT_REF_NAME}" == "master" ]; then
          echo "Did not push image on master. Failing build"
          exit 1
        fi
        if [ -n "$CI" ]; then
            IMAGE_NAME_SAVE="$(echo ${image_full_name} | sed -e 's/\//__/g').tar"
            IMAGE_SAVE="${ARTIFACTS_FOLDER}/${IMAGE_NAME_SAVE}"
            echo "Creating artifact of docker image at ${IMAGE_SAVE}"
            docker save -o "${IMAGE_SAVE}" "${image_full_name}"
            IMAGE_ARTIFACTS="${IMAGE_SAVE},${IMAGE_ARTIFACTS}"
            gzip "${IMAGE_SAVE}"
            "${DOCKER_SRC_DIR}/post_github_comment.py" "${image_full_name}" "--is_contribution"
            cat << EOF
-------------------------
Docker image [$image_full_name] has been saved as an artifact.
--------------------------
EOF
        fi
    fi

}

# default compare branch against master
DIFF_COMPARE=origin/master...${CI_COMMIT_SHA}

if [ -z "${CI_COMMIT_SHA}" ]; then
    echo "CI_COMMIT_SHA not set. Assuming local testing."
    CI_COMMIT_SHA=testing
    DOCKER_ORG=${DOCKER_ORG:-devtesting}
    
    if [ -z "${CI_COMMIT_REF_NAME}" ]; then
        # simply compare against origin/master
        DIFF_COMPARE=origin/master
    fi
fi

if [[ ! $(which pyenv) ]] && [[ -n "${GITLAB_CI}" ]]; then
    echo "pyenv not found. setting up necessary env for pyenv on CI";\
    export PATH="$HOME/.pyenv/bin:$PATH"
    eval "$(pyenv init -)"
    eval "$(pyenv virtualenv-init -)"
    pyenv shell system "$(pyenv versions --bare | grep 3.10)"
fi

echo "default python versions: "
python --version || echo "python not found"
python3 --version || echo "python3 not found"
if [[ $(which pyenv) ]]; then
    echo "pyenv versions:"
    pyenv versions
fi

echo "=========== docker info =============="
docker info
echo "========================="

if [[ -n "$1" ]]; then
    if [[ ! -d  "${SCRIPT_DIR}/$1" ]]; then
        echo "Image: [$1] specified as command line parameter but directory not found: [${SCRIPT_DIR}/$1]"
        exit 1
    fi
    DIFF_COMPARE="ALL"
    DOCKER_INCLUDE_GREP="/${1}$"
fi

if [ "${CI_COMMIT_REF_NAME}" == "master" ]; then
    DIFF_COMPARE="HEAD^1...HEAD"
    DOCKER_ORG=demisto
fi

echo "DOCKER_ORG: ${DOCKER_ORG}, DIFF_COMPARE: [${DIFF_COMPARE}], SCRIPT_DIR: [${SCRIPT_DIR}], BRANCH: ${CI_COMMIT_REF_NAME}, PWD: [${CURRENT_DIR}]"

ARTIFACTS_FOLDER="${ARTIFACTS_FOLDER:-artifacts}"
if [[ ! -d "${ARTIFACTS_FOLDER}" ]]; then
  mkdir -p "${ARTIFACTS_FOLDER}"
fi

# echo to bash env to be used in future steps
echo $DIFF_COMPARE > $ARTIFACTS_FOLDER/diff_compare.txt
echo $SCRIPT_DIR > $ARTIFACTS_FOLDER/script_dir.txt
echo $CURRENT_DIR > $ARTIFACTS_FOLDER/current_dir.txt
echo $DOCKER_INCLUDE_GREP > $ARTIFACTS_FOLDER/docker_include_grep.txt

total=$(find $SCRIPT_DIR -maxdepth 1 -mindepth 1 -type  d -print | wc -l)
count=0
errors=()
for docker_dir in `find $SCRIPT_DIR -maxdepth 1 -mindepth 1 -type  d -print | sort`; do
    echo "Checking dir: ${docker_dir} against ${DIFF_COMPARE}"
    if [[ ${DIFF_COMPARE} = "ALL" ]] || [[ $(git --no-pager diff "${DIFF_COMPARE}" --name-status -- "${docker_dir}") ]]; then
        if [ -n "${DOCKER_INCLUDE_GREP}" ] && [ -z "$(echo ${docker_dir} | grep -E ${DOCKER_INCLUDE_GREP})" ]; then
            [[ -z "$1" ]] && echo "Skipping dir: '${docker_dir}' as not included in grep expression DOCKER_INCLUDE_GREP: '${DOCKER_INCLUDE_GREP}'"
            continue
        fi
        count=$((count+1))
        echo "=============== `date`: Starting docker build in dir: ${docker_dir} ($count of $total) ==============="
        docker_build ${docker_dir}
        cd ${CURRENT_DIR}
        echo ">>>>>>>>>>>>>>> `date`: Done docker build <<<<<<<<<<<<<"
    fi
done
if [ ${#errors[@]} != 0 ]; then
  for err in "${errors[@]}"; do
    red_error "$err"
  done
  exit 1
fi


if [ -n "$PUSHED_DOCKERS" ]; then
  echo "${PUSHED_DOCKERS}" > "${ARTIFACTS_FOLDER}/pushed_dockers.txt"
  echo "Successfully pushed:${PUSHED_DOCKERS}"
else
    echo "No dockers were built and pushed"
fi

if [ -n "${IMAGE_ARTIFACTS}" ]; then
  echo "${IMAGE_ARTIFACTS}" > "${ARTIFACTS_FOLDER}/image_artifacts.txt"
  echo "Successfully saved:${IMAGE_ARTIFACTS}"
else
    echo "No image artifacts were saved"
fi
