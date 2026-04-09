#!/usr/bin/env bash

# exit on errors
set -e

# Associative array to track failed docker images in upload mode
# Keys: image_name, Values: step that failed
declare -A FAILED_DOCKERS

# Record a docker image failure and return the appropriate exit code.
# In upload mode: records to FAILED_DOCKERS and returns 0 (continue).
# In non-upload mode: logs the error and returns 1 (fail).
# Usage: record_failure "image" "step" "message"; return $?
# param $1: image name
# param $2: step that failed (build, validation, push)
# param $3: error message
function record_failure {
    local img="$1"
    local step="$2"
    local err_msg="$3"
    red_error "Image '${img}' failed at step '${step}': ${err_msg}"
    if [ "${UPLOAD_MODE}" = "true" ]; then
        FAILED_DOCKERS["${img}"]="${step}"
        return 0
    fi
    return 1
}

# Write the failed dockers JSON report to ARTIFACTS_FOLDER
function write_failed_dockers_report {
    local report_file="${ARTIFACTS_FOLDER}/failed_dockers.json"
    if [ ${#FAILED_DOCKERS[@]} -eq 0 ]; then
        echo '{}' > "${report_file}"
    else
        echo '{' > "${report_file}"
        local first=true
        for img in "${!FAILED_DOCKERS[@]}"; do
            if [ "${first}" = true ]; then
                first=false
            else
                echo ',' >> "${report_file}"
            fi
            # Escape any double quotes in the image name (unlikely but safe)
            local escaped_img="${img//\"/\\\"}"
            local escaped_step="${FAILED_DOCKERS[$img]//\"/\\\"}"
            printf '  "%s": {"step": "%s"}' "${escaped_img}" "${escaped_step}" >> "${report_file}"
        done
        echo '' >> "${report_file}"
        echo '}' >> "${report_file}"
    fi
    echo "Failed dockers report written to ${report_file}"
    cat "${report_file}"
}

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

if [ -n "$GITLAB_CI" ]; then
    DOCKER_LOGIN_DONE=${DOCKER_LOGIN_DONE:-no}
else
    DOCKER_LOGIN_DONE=${DOCKER_LOGIN_DONE:-yes}
fi
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
        return 3;
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
    if [ "${DRY_RUN}" = "true" ]; then
        echo "[DRY-RUN] Would have committed docker trust data"
        return
    fi
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
            if [ "${UPLOAD_MODE}" = "true" ]; then
                echo "Continuing in upload mode despite trust commit failure"
                cd "$cwd"
                return 1
            fi
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
        set +e
        ${PY3CMD} "${DOCKER_SRC_DIR}"/add_image_to_deprecated_or_internal_list.py "${DOCKER_ORG_DEMISTO}"/"${image_name}" "${reason}" "${DOCKER_SRC_DIR}"/deprecated_images.json
        local deprecated_rc=$?
        set -e
        if [ $deprecated_rc -ne 0 ]; then
            echo "Warning: add_image_to_deprecated_or_internal_list.py failed with exit code ${deprecated_rc}"
            record_failure "${image_name}" "build" "add_image_to_deprecated_or_internal_list.py failed with exit code ${deprecated_rc}"
            return $?
        fi
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
          set +e
          pipenv install --deploy # fails if lock is outdated
          local pipenv_rc=$?
          set -e
          if [ $pipenv_rc -ne 0 ]; then
              echo "pipenv install --deploy failed with exit code ${pipenv_rc}"
              record_failure "${image_name}" "build" "pipenv install --deploy failed with exit code ${pipenv_rc}"
              return $?
          fi
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
      set +e
      poetry export -f requirements.txt --output requirements.txt --without-hashes
      local poetry_rc=$?
      set -e
      if [ $poetry_rc -ne 0 ]; then
          echo "poetry export failed with exit code ${poetry_rc}"
          record_failure "${image_name}" "build" "poetry export failed with exit code ${poetry_rc}"
          return $?
      fi
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
    if ! docker_login; then
        red_error "FATAL: docker login failed for image ${image_name}. Cannot proceed."
        if [ "${UPLOAD_MODE}" = "true" ]; then
            record_failure "${image_name}" "build" "docker login failed - fatal error"
            write_failed_dockers_report
        fi
        exit 1
    fi
    echo "### DOCKER LOGIN DONE ###"

    set +e
    docker buildx build -f "$tmp_dir/Dockerfile" . -t ${image_full_name} \
        --label "org.opencontainers.image.authors=Demisto <containers@demisto.com>" \
        --label "org.opencontainers.image.version=${VERSION}" \
        --label "org.opencontainers.image.revision=${CI_COMMIT_SHA}"
    local build_exit_code=$?
    set -e

    if [ $build_exit_code -ne 0 ]; then
        rm -rf "$tmp_dir"
        record_failure "${image_name}" "build" "docker buildx build failed with exit code ${build_exit_code}"
        return $?
    fi

    if [[ -e "dynamic_version.sh" ]]; then
      echo "dynamic_version.sh file was found"
      set +e
      dynamic_version=$(docker run --rm -i "$image_full_name" sh < dynamic_version.sh)
      local dv_exit_code=$?
      set -e
      if [ $dv_exit_code -ne 0 ]; then
          rm -rf "$tmp_dir"
          record_failure "${image_name}" "build" "dynamic_version.sh execution failed with exit code ${dv_exit_code}"
          return $?
      fi
      if [ -z "${dynamic_version}" ]; then
          rm -rf "$tmp_dir"
          record_failure "${image_name}" "build" "dynamic_version.sh returned empty version"
          return $?
      fi
      echo "dynamic_version $dynamic_version"
      VERSION="${dynamic_version}.${REVISION}"
      image_full_name="${DOCKER_ORG}/${image_name}:${VERSION}"

      # add the last layer and rebuild. Everything should be cached besides this layer
      echo "ENV DOCKER_IMAGE=$image_full_name" >> "$tmp_dir/Dockerfile"

      echo "running docker build again with tag $image_full_name"

      set +e
      docker buildx build -f "$tmp_dir/Dockerfile" . -t ${image_full_name} \
        --label "org.opencontainers.image.authors=Demisto <containers@demisto.com>" \
        --label "org.opencontainers.image.version=${VERSION}" \
        --label "org.opencontainers.image.revision=${CI_COMMIT_SHA}"
      local rebuild_exit_code=$?
      set -e

      if [ $rebuild_exit_code -ne 0 ]; then
          rm -rf "$tmp_dir"
          record_failure "${image_name}" "build" "docker buildx rebuild (dynamic version) failed with exit code ${rebuild_exit_code}"
          return $?
      fi
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
    set +e
    PYTHON_VERSION=$(docker inspect "$image_full_name" | jq -r '.[].Config.Env[]|select(match("^PYTHON_VERSION"))|.[index("=")+1:]')
    local inspect_rc=$?
    set -e
    if [ $inspect_rc -ne 0 ]; then
        echo "Warning: docker inspect failed with exit code ${inspect_rc} for image ${image_full_name}"
        PYTHON_VERSION=""
    fi
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
        set +e
        $PY3CMD ${DOCKER_SRC_DIR}/verify_licenses.py ${image_full_name}
        local license_exit_code=$?
        set -e
        if [ $license_exit_code -ne 0 ]; then
            record_failure "${image_name}" "validation" "verify_licenses.py failed with exit code ${license_exit_code}"
            return $?
        fi
    fi
    local filename
    while IFS= read -r -d '' filename; do
        echo "==========================="
        echo "Verifying docker image by running the python script $filename within the docker image"
        set +e
        cat "${filename}" | docker run --rm -i ${image_full_name} python '-'
        local verify_exit_code=$?
        set -e
        if [ $verify_exit_code -ne 0 ]; then
            record_failure "${image_name}" "validation" "verify script ${filename} failed with exit code ${verify_exit_code}"
            return $?
        fi
    done < <(find . -name "*verify.py" -print0)

    if [ -f "verify.ps1" ]; then
        echo "==========================="
        echo "Verifying docker image by running the pwsh script verify.ps1 within the docker image"
        # use "tee" as powershell doesn't fail on throw when run with -c
        set +e
        cat verify.ps1 | docker run --rm -i ${image_full_name} sh -c 'tee > verify.ps1; pwsh verify.ps1'
        local ps_verify_exit_code=$?
        set -e
        if [ $ps_verify_exit_code -ne 0 ]; then
            record_failure "${image_name}" "validation" "verify.ps1 failed with exit code ${ps_verify_exit_code}"
            return $?
        fi
    fi
    docker_trust=0
    if sign_setup; then
        docker_trust=1
        echo "using DOCKER_TRUST=${docker_trust} DOCKER_CONFIG=${DOCKER_CONFIG}"
    fi

    if [ -n "$CR_REPO" ] && cr_login; then
        if [ "${DRY_RUN}" = "true" ]; then
            echo "[DRY-RUN] Would have pushed to CR: ${CR_REPO}/${image_full_name}"
        else
            set +e
            docker tag ${image_full_name} ${CR_REPO}/${image_full_name}
            local cr_tag_exit_code=$?
            if [ $cr_tag_exit_code -ne 0 ]; then
                set -e
                record_failure "${image_name}" "push" "docker tag for CR failed with exit code ${cr_tag_exit_code}"
                return $?
            fi
            docker push ${CR_REPO}/${image_full_name} > /dev/null
            local cr_push_exit_code=$?
            set -e
            if [ $cr_push_exit_code -ne 0 ]; then
                record_failure "${image_name}" "push" "docker push to CR failed with exit code ${cr_push_exit_code}"
                return $?
            fi
            echo "Done docker push for cr: ${image_full_name}"
        fi
    else
        echo "Skipping docker push for cr"
    fi

    DOCKER_LOGIN_DONE="no"
    if docker_login; then
        if [ "${DRY_RUN}" = "true" ]; then
            echo "[DRY-RUN] Would have pushed to Docker Hub: ${image_full_name}"
        else
            echo "Done docker login"
            set +e
            env DOCKER_CONTENT_TRUST=$docker_trust DOCKER_CONFIG="${DOCKER_CONFIG}"  docker push ${image_full_name}
            local dh_push_exit_code=$?
            set -e
            if [ $dh_push_exit_code -ne 0 ]; then
                record_failure "${image_name}" "push" "docker push to Docker Hub failed with exit code ${dh_push_exit_code}"
                return $?
            fi
            echo "Done docker push for: ${image_full_name}"
            PUSHED_DOCKERS="${image_full_name},$PUSHED_DOCKERS"
            echo "debug pushed_dockers $PUSHED_DOCKERS"
            if [[ "$docker_trust" == "1" ]]; then
                commit_dockerfiles_trust
            fi
        fi
        POST_COMMENT_ARGS=("${image_full_name}")
        if [ "${UPLOAD_MODE}" = "true" ]; then
            POST_COMMENT_ARGS+=("--upload" "--files-to-prs" "${FILES_TO_PRS}")
        fi
        if [ "${DRY_RUN}" = "true" ]; then
            POST_COMMENT_ARGS+=("--dry-run")
        fi
        if ! "${DOCKER_SRC_DIR}/post_github_comment.py" "${POST_COMMENT_ARGS[@]}"; then
            echo "Failed post_github_comment.py. Will stop build only if not on master"
            if [ "${CI_COMMIT_REF_NAME}" == "master" ]; then
                echo "Continuing as we are on master branch..."
            else
                record_failure "${image_name}" "push" "post_github_comment.py failed"
                local pgc_rc=$?
                if [ $pgc_rc -eq 0 ]; then
                    return 0
                fi
                echo "failing build!!"
                exit 5
            fi
        fi
    else
        echo "Skipping docker push"
        record_failure "${image_name}" "push" "docker login failed, could not push image"
        local dl_rc=$?
        if [ $dl_rc -eq 0 ]; then
            return 0
        fi
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
            POST_COMMENT_ARGS=("${image_full_name}" "--is_contribution")
            if [ "${DRY_RUN}" = "true" ]; then
                POST_COMMENT_ARGS+=("--dry-run")
            fi
            "${DOCKER_SRC_DIR}/post_github_comment.py" "${POST_COMMENT_ARGS[@]}"
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

# PARSE ARGUMENTS
UPLOAD_MODE="false"
DRY_RUN="false"
docker_image_to_build=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --upload) UPLOAD_MODE="true"; shift;;
        --last-upload-commit) LAST_UPLOAD_COMMIT="$2"; shift 2;;
        --files-to-prs) FILES_TO_PRS="$2"; shift 2;;
        --dry-run) DRY_RUN="true"; shift;;
        --*) echo "Unknown option: $1"; exit 1;;
        *) docker_image_to_build="$1"; shift;;
    esac
done

if [[ -n "${docker_image_to_build}" ]]; then
    if [[ ! -d  "${SCRIPT_DIR}/${docker_image_to_build}" ]]; then
        echo "Image: [${docker_image_to_build}] specified as command line parameter but directory not found: [${SCRIPT_DIR}/${docker_image_to_build}]"
        exit 1
    fi
    DIFF_COMPARE="ALL"
    DOCKER_INCLUDE_GREP="/${docker_image_to_build}$"
fi

if [ "${UPLOAD_MODE}" = "true" ]; then
    if [ -z "${LAST_UPLOAD_COMMIT}" ]; then
        echo "--last-upload-commit is required for --upload mode"
        exit 1
    fi
    if [ -z "${FILES_TO_PRS}" ]; then
        echo "--files-to-prs is required for --upload mode"
        exit 1
    fi
    DIFF_COMPARE="${LAST_UPLOAD_COMMIT}...${CI_COMMIT_SHA}"
    DOCKER_ORG=demisto
    if [ "${DRY_RUN}" = "true" ]; then
        DOCKER_ORG=devdemisto
        echo "[DRY-RUN] Overriding DOCKER_ORG to devdemisto"
    fi
    echo "Running in upload mode. Comparing against last upload commit: ${LAST_UPLOAD_COMMIT}"
fi

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

if [ "${CI_COMMIT_REF_NAME}" == "master" ] && [ "${UPLOAD_MODE}" = "false" ]; then
    DIFF_COMPARE="HEAD^1...HEAD"
    DOCKER_ORG=demisto
    if [ "${DRY_RUN}" = "true" ]; then
        DOCKER_ORG=devdemisto
        echo "[DRY-RUN] Overriding DOCKER_ORG to devdemisto"
    fi
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
            [[ -z "${docker_image_to_build}" ]] && echo "Skipping dir: '${docker_dir}' as not included in grep expression DOCKER_INCLUDE_GREP: '${DOCKER_INCLUDE_GREP}'"
            continue
        fi
        count=$((count+1))
        echo "=============== `date`: Starting docker build in dir: ${docker_dir} ($count of $total) ==============="
        if [ "${UPLOAD_MODE}" = "true" ]; then
            # In upload mode, don't let a single image failure stop the entire build
            set +e
            docker_build ${docker_dir}
            build_rc=$?
            set -e
            if [ $build_rc -ne 0 ]; then
                failed_img_name=$(basename "${docker_dir}")
                record_failure "${failed_img_name}" "build" "docker_build function returned non-zero exit code ${build_rc}"
            fi
        else
            docker_build ${docker_dir}
        fi
        cd ${CURRENT_DIR}
        echo ">>>>>>>>>>>>>>> `date`: Done docker build <<<<<<<<<<<<<"
    fi
done
if [ ${#errors[@]} != 0 ]; then
  for err in "${errors[@]}"; do
    red_error "$err"
  done
  if [ "${UPLOAD_MODE}" = "true" ]; then
    echo "Errors found but continuing in upload mode (errors logged above)"
  else
    exit 1
  fi
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

# Write the failed dockers JSON report (always, even if empty)
if [ "${UPLOAD_MODE}" = "true" ]; then
    write_failed_dockers_report
fi
