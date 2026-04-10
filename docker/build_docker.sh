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
SUCCEEDED_IMAGES=()
IMAGE_ARTIFACTS=""
CURRENT_DIR=$(pwd)
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
DOCKER_SRC_DIR=${SCRIPT_DIR}
if [[ "${DOCKER_SRC_DIR}" != /* ]]; then
    DOCKER_SRC_DIR="${CURRENT_DIR}/${SCRIPT_DIR}"
fi
DOCKERFILES_TRUST_DIR="$(cd "${DOCKER_SRC_DIR}/.." && pwd)"
DOCKERFILES_TRUST_DIR="${DOCKERFILES_TRUST_DIR}/dockerfiles-trust"


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
    done < "$1"


}

red_error() {
    echo -e "\033[0;31m$1\033[0m"
}

# -- Terminal width detection (fallback to 160 for CI / non-interactive) --
TERM_WIDTH=$(tput cols 2>/dev/null || echo 160)
if [ "${TERM_WIDTH}" -lt 40 ]; then
    TERM_WIDTH=160
fi

# -- Banner / separator helpers (ASCII-safe, no special unicode) ----------
# Print a full-width line of a given character
# param $1: fill character (default "=")
function print_separator {
    local ch="${1:-=}"
    printf '%*s\n' "${TERM_WIDTH}" '' | tr ' ' "${ch}"
}

# Print a centered text line padded to terminal width
# param $1: text to center
function print_centered {
    local text="$1"
    local text_len=${#text}
    local pad_total=$((TERM_WIDTH - text_len))
    local pad_left=$((pad_total / 2))
    local pad_right=$((pad_total - pad_left))
    if [ "${pad_total}" -le 0 ]; then
        echo "$text"
    else
        printf '%*s%s%*s\n' "$pad_left" '' "$text" "$pad_right" ''
    fi
}

# Print a boxed banner with ### borders, auto-sized to terminal width
# param $@: lines of text to display inside the box
function print_box_banner {
    # Layout: "###   " (6) + inner_width + "   ###" (6) = inner_width + 12
    # Separator: "###" (3) + sep_inner + "###" (3) = sep_inner + 6
    # For alignment: inner_width + 12 = sep_inner + 6  =>  inner_width = TERM_WIDTH - 12
    local inner_width=$((TERM_WIDTH - 12))
    if [ "${inner_width}" -lt 20 ]; then
        inner_width=20
    fi
    local sep_inner=$((inner_width + 6))  # keeps total width consistent
    echo ""
    printf '###%*s###\n' "${sep_inner}" '' | tr ' ' '='
    printf '###%*s###\n' "${sep_inner}" ''
    for line_text in "$@"; do
        printf '###   %-*s   ###\n' "${inner_width}" "${line_text}"
    done
    printf '###%*s###\n' "${sep_inner}" ''
    printf '###%*s###\n' "${sep_inner}" '' | tr ' ' '='
}

# Print a simple section header with separator lines
# param $1: header text
function print_section_header {
    local text="$1"
    echo ""
    print_separator "="
    print_centered "  ${text}  "
    print_separator "="
    echo ""
}

# Print a sub-separator (shorter, for minor sections)
# param $1: fill character (default "-")
function print_sub_separator {
    local ch="${1:--}"
    printf '%*s\n' "${TERM_WIDTH}" '' | tr ' ' "${ch}"
}

# -- GitLab CI section helpers ---------------------------------------------
# Opens a collapsed section in GitLab CI; no-op otherwise
# param $1: section id (alphanumeric + underscore)
# param $2: section header text
function gitlab_section_start {
    if [ -n "${GITLAB_CI}" ]; then
        local section_id="$1"
        local header="$2"
        # \e[0K clears the line; [collapsed=true] makes it collapsed by default
        printf "\e[0Ksection_start:%s:%s[collapsed=true]\r\e[0K%s\n" "$(date +%s)" "${section_id}" "${header}"
    fi
}

# Closes a GitLab CI section; no-op otherwise
# param $1: section id
function gitlab_section_end {
    if [ -n "${GITLAB_CI}" ]; then
        local section_id="$1"
        printf "\e[0Ksection_end:%s:%s\r\e[0K\n" "$(date +%s)" "${section_id}"
    fi
}

# -- Logging helper -------------------------------------------------------
# Prefixes every line from stdin with:
#   [2024-07-21 07:18:07] [ 1/10] [image_name   ] <line>
# param $1: image name
# param $2: current 1-based index
# param $3: total count
# param $4: max image name length (for padding)
# param $5: count field width (for padding)
function log_prefix {
    local img="$1" idx="$2" tot="$3" pad_name="$4" pad_count="$5"
    while IFS= read -r line || [ -n "$line" ]; do
        printf "[%s] [%${pad_count}d/%d] [%-${pad_name}s] %s\n" \
            "$(date '+%Y-%m-%d %H:%M:%S')" "$idx" "$tot" "$img" "$line"
    done
}

if [ -n "$GITLAB_CI" ]; then
    DOCKER_LOGIN_DONE=${DOCKER_LOGIN_DONE:-no}
    # Use plain buildkit progress in CI to avoid noisy progress bars
    export BUILDKIT_PROGRESS=plain
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
        if ! docker login -u "${DOCKERHUB_USER}"; then
            echo "Failed docker login for user: ${DOCKERHUB_USER}"
            return 2;
        fi
    else
        if ! docker login -u "${DOCKERHUB_USER}" -p "${DOCKERHUB_PASSWORD}"; then
            echo "Failed docker login for user: ${DOCKERHUB_USER}"
            return 2;
        fi
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
    cr_url="https://$(echo "${CR_REPO}" | cut -d / -f 1)"
    if [ -z "$CR_PASSWORD" ]; then
        #for local testing scenarios to allow password to be passed via stdin
        if ! docker login -u "${CR_USER}" "${cr_url}"; then
            echo "Failed docker login to CR repo"
            return 3;
        fi
    else
        if ! docker login -u "${CR_USER}" -p "${CR_PASSWORD}" "${cr_url}"; then
            echo "Failed docker login to CR repo"
            return 3;
        fi
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
    image_name=$(basename "$1")
    echo "Starting build for dir: $1, image: ${image_name}, pwd: $(pwd)"
    cd "$1"
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
          print_separator "#"
          cat requirements.txt
          print_separator "#"
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
      print_separator "#"
      cat requirements.txt
      print_separator "#"

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

    print_sub_separator "-"
    echo "  DOCKER LOGIN START"
    print_sub_separator "-"
    if ! docker_login; then
        red_error "FATAL: docker login failed for image ${image_name}. Cannot proceed."
        if [ "${UPLOAD_MODE}" = "true" ]; then
            record_failure "${image_name}" "build" "docker login failed - fatal error"
            write_failed_dockers_report
        fi
        exit 1
    fi
    print_sub_separator "-"
    echo "  DOCKER LOGIN DONE"
    print_sub_separator "-"

    set +e
    docker buildx build -f "$tmp_dir/Dockerfile" . -t "${image_full_name}" \
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
      docker buildx build -f "$tmp_dir/Dockerfile" . -t "${image_full_name}" \
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

    if [ "${del_requirements}" = "yes" ]; then
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

    print_separator "="
    print_centered "$(date): Starting version verification on image: ${image_name}"
    print_separator "="
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
        if ! output=$("$PY3CMD" "${DOCKER_SRC_DIR}"/verify_version_matching.py "${PYTHON_VERSION}" "${version_from_file}" "${image_name}" "${file_name}"); then
            errors+=("$output")
        fi
    fi


    if [[ "$(prop 'devonly')" ]]; then
        echo "Skipping license verification for devonly image"
    else
        PY3CMD="python3"
        set +e
        "$PY3CMD" "${DOCKER_SRC_DIR}/verify_licenses.py" "${image_full_name}"
        local license_exit_code=$?
        set -e
        if [ $license_exit_code -ne 0 ]; then
            record_failure "${image_name}" "validation" "verify_licenses.py failed with exit code ${license_exit_code}"
            return $?
        fi
    fi
    local filename
    while IFS= read -r -d '' filename; do
        print_sub_separator "-"
        echo "Verifying docker image by running the python script $filename within the docker image"
        set +e
        cat "${filename}" | docker run --rm -i "${image_full_name}" python '-'
        local verify_exit_code=$?
        set -e
        if [ $verify_exit_code -ne 0 ]; then
            record_failure "${image_name}" "validation" "verify script ${filename} failed with exit code ${verify_exit_code}"
            return $?
        fi
    done < <(find . -name "*verify.py" -print0)

    if [ -f "verify.ps1" ]; then
        print_sub_separator "-"
        echo "Verifying docker image by running the pwsh script verify.ps1 within the docker image"
        # use "tee" as powershell doesn't fail on throw when run with -c
        set +e
        cat verify.ps1 | docker run --rm -i "${image_full_name}" sh -c 'tee > verify.ps1; pwsh verify.ps1'
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
            docker tag "${image_full_name}" "${CR_REPO}/${image_full_name}"
            local cr_tag_exit_code=$?
            if [ $cr_tag_exit_code -ne 0 ]; then
                set -e
                record_failure "${image_name}" "push" "docker tag for CR failed with exit code ${cr_tag_exit_code}"
                return $?
            fi
            docker push "${CR_REPO}/${image_full_name}" > /dev/null
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
            env DOCKER_CONTENT_TRUST="$docker_trust" DOCKER_CONFIG="${DOCKER_CONFIG}" docker push "${image_full_name}"
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
            IMAGE_NAME_SAVE="$(echo "${image_full_name}" | sed -e 's/\//__/g').tar"
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
            print_sub_separator "-"
            echo "Docker image [$image_full_name] has been saved as an artifact."
            print_sub_separator "-"
        fi
    fi

}

# default compare branch against master
DIFF_COMPARE=origin/master...${CI_COMMIT_SHA}

# -- Usage / Help ----------------------------------------------------------
function usage {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] [IMAGE_NAME]

Build, verify, and push Docker images that have changed relative to a base commit.

Positional arguments:
  IMAGE_NAME              Build only the specified image (by directory name).
                          When provided, DIFF_COMPARE is set to ALL (build regardless of diff).

Options:
  --upload                Run in upload/production mode. Requires --last-upload-commit
                          and --files-to-prs. Failures are recorded but do not stop the build.
  --last-upload-commit SHA
                          The commit SHA to compare against in upload mode.
  --files-to-prs PATH    Path to the files_to_prs.json mapping file (upload mode).
  --dry-run               Simulate the build: skip docker push and github comments.
  -h, --help              Show this help message and exit.

Environment variables:
  CI_COMMIT_SHA           Current commit SHA (auto-set in CI).
  CI_COMMIT_REF_NAME      Current branch name (auto-set in CI).
  CI_PIPELINE_ID          Pipeline/revision ID (auto-set in CI).
  DOCKER_ORG              Docker Hub organization (default: devdemisto, or demisto on master).
  DOCKERHUB_USER          Docker Hub username for login.
  DOCKERHUB_PASSWORD      Docker Hub password for login.
  CR_REPO                 Container registry repo URL for secondary push.
  CR_USER / CR_PASSWORD   Container registry credentials.
  ARTIFACTS_FOLDER        Directory for build artifacts (default: artifacts).
  GITLAB_CI               Set automatically in GitLab CI runners.

Examples:
  # Build all changed images (CI default):
  ./$(basename "$0")

  # Build a single image locally:
  ./$(basename "$0") python3-deb

  # Dry-run upload mode:
  ./$(basename "$0") --upload --last-upload-commit abc123 --files-to-prs files.json --dry-run
EOF
}

# PARSE ARGUMENTS
UPLOAD_MODE="false"
DRY_RUN="false"
docker_image_to_build=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0;;
        --upload) UPLOAD_MODE="true"; shift;;
        --last-upload-commit) LAST_UPLOAD_COMMIT="$2"; shift 2;;
        --files-to-prs) FILES_TO_PRS="$2"; shift 2;;
        --dry-run) DRY_RUN="true"; shift;;
        --*) echo "Unknown option: $1"; usage; exit 1;;
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

if [ "${CI_COMMIT_REF_NAME}" == "master" ] && [ "${UPLOAD_MODE}" = "false" ]; then
    DIFF_COMPARE="HEAD^1...HEAD"
    DOCKER_ORG=demisto
    if [ "${DRY_RUN}" = "true" ]; then
        DOCKER_ORG=devdemisto
    fi
fi

# ============================================================================
# STARTUP INFO -- show all configuration in a nicely formatted box
# ============================================================================
_py_ver=$(python --version 2>&1 || echo "python not found")
_py3_ver=$(python3 --version 2>&1 || echo "python3 not found")

print_box_banner \
    "DOCKER BUILD -- STARTUP CONFIGURATION" \
    "" \
    "Date             : $(date '+%Y-%m-%d %H:%M:%S')" \
    "Branch           : ${CI_COMMIT_REF_NAME:-N/A}" \
    "Commit SHA       : ${CI_COMMIT_SHA:-N/A}" \
    "Pipeline ID      : ${CI_PIPELINE_ID:-N/A}" \
    "" \
    "DOCKER_ORG       : ${DOCKER_ORG:-devdemisto}" \
    "DIFF_COMPARE     : ${DIFF_COMPARE}" \
    "DOCKER_SRC_DIR   : ${DOCKER_SRC_DIR}" \
    "TRUST_DIR        : ${DOCKERFILES_TRUST_DIR}" \
    "SCRIPT_DIR       : ${SCRIPT_DIR}" \
    "PWD              : ${CURRENT_DIR}" \
    "" \
    "Upload Mode      : ${UPLOAD_MODE}" \
    "Dry Run          : ${DRY_RUN}" \
    "" \
    "Python           : ${_py_ver}" \
    "Python3          : ${_py3_ver}"

# -- pyenv info (if available) --
if [[ $(which pyenv 2>/dev/null) ]]; then
    print_section_header "pyenv versions"
    pyenv versions
    print_separator "="
fi

# -- Docker Info (collapsed in GitLab CI) --
gitlab_section_start "docker_info" "Docker Engine Info"
print_section_header "docker info"
docker info
print_separator "="
gitlab_section_end "docker_info"

ARTIFACTS_FOLDER="${ARTIFACTS_FOLDER:-artifacts}"
if [[ ! -d "${ARTIFACTS_FOLDER}" ]]; then
  mkdir -p "${ARTIFACTS_FOLDER}"
fi

# Persist build context to artifacts for use in subsequent CI steps
print_section_header "Saving build context to artifacts"
echo "$DIFF_COMPARE" > "$ARTIFACTS_FOLDER/diff_compare.txt"          # git diff range used for change detection
echo "$SCRIPT_DIR" > "$ARTIFACTS_FOLDER/script_dir.txt"              # absolute path to the docker/ script directory
echo "$CURRENT_DIR" > "$ARTIFACTS_FOLDER/current_dir.txt"            # working directory at script start
echo "$DOCKER_INCLUDE_GREP" > "$ARTIFACTS_FOLDER/docker_include_grep.txt"  # grep filter for specific image (if any)
echo "  diff_compare.txt          : ${DIFF_COMPARE}"
echo "  script_dir.txt            : ${SCRIPT_DIR}"
echo "  current_dir.txt           : ${CURRENT_DIR}"
echo "  docker_include_grep.txt   : ${DOCKER_INCLUDE_GREP:-<empty>}"
print_separator "="

# ============================================================================
# PHASE 1: DISCOVERY -- find all changed docker directories before building
# ============================================================================
print_section_header "DISCOVERY PHASE: Scanning for changed Docker images..."
echo "  DIFF_COMPARE: ${DIFF_COMPARE}"
echo ""

# Count total directories for progress display
ALL_DOCKER_DIRS=()
while IFS= read -r d; do
    ALL_DOCKER_DIRS+=("$d")
done < <(find "$SCRIPT_DIR" -maxdepth 1 -mindepth 1 -type d -print | sort)
discovery_total=${#ALL_DOCKER_DIRS[@]}
discovery_count_width=${#discovery_total}

CHANGED_DOCKER_DIRS=()
discovery_idx=0
for docker_dir in "${ALL_DOCKER_DIRS[@]}"; do
    discovery_idx=$((discovery_idx + 1))
    echo "Checking dir: ${docker_dir}" | log_prefix "discovery" "${discovery_idx}" "${discovery_total}" 15 "${discovery_count_width}"
    if [[ ${DIFF_COMPARE} = "ALL" ]] || [[ $(git --no-pager diff "${DIFF_COMPARE}" --name-status -- "${docker_dir}") ]]; then
        if [ -n "${DOCKER_INCLUDE_GREP}" ] && ! echo "${docker_dir}" | grep -qE "${DOCKER_INCLUDE_GREP}"; then
            [[ -z "${docker_image_to_build}" ]] && echo "Skipping: not in DOCKER_INCLUDE_GREP" | log_prefix "discovery" "${discovery_idx}" "${discovery_total}" 15 "${discovery_count_width}"
            continue
        fi
        CHANGED_DOCKER_DIRS+=("${docker_dir}")
        echo ">> Queued: $(basename "${docker_dir}")" | log_prefix "discovery" "${discovery_idx}" "${discovery_total}" 15 "${discovery_count_width}"
    fi
done

total=${#CHANGED_DOCKER_DIRS[@]}

print_section_header "DISCOVERY COMPLETE: Found ${total} Docker image(s) to build (scanned ${discovery_total} directories)"

if [ "${total}" -eq 0 ]; then
    echo "No changed Docker images found. Nothing to build."
fi

# Compute the max image name length for padded/aligned log output
max_name_len=0
for docker_dir in "${CHANGED_DOCKER_DIRS[@]}"; do
    _img_name=$(basename "${docker_dir}")
    name_len=${#_img_name}
    if [ "${name_len}" -gt "${max_name_len}" ]; then
        max_name_len=${name_len}
    fi
done

# Width of the count field (e.g. if total=100, count_width=3)
count_width=${#total}

# -- tqdm-style progress bar (ASCII-safe) ----------------------------------
# param $1: current (1-based)
# param $2: total
# param $3: bar width (default 40)
function progress_bar {
    local current=$1 total=$2 width=${3:-40}
    if [ "${total}" -eq 0 ]; then return; fi
    local pct=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    local bar=""
    for ((i = 0; i < filled; i++)); do bar+="#"; done
    for ((i = 0; i < empty; i++)); do bar+="."; done
    local elapsed=""
    if [ -n "${BUILD_START_EPOCH}" ]; then
        local now
        now=$(date +%s)
        local secs=$((now - BUILD_START_EPOCH))
        elapsed=" elapsed $(printf '%02d:%02d:%02d' $((secs/3600)) $(( (secs%3600)/60 )) $((secs%60)))"
    fi
    printf "\n  Progress: |%s| %3d%% (%d/%d)%s\n\n" "$bar" "$pct" "$current" "$total" "$elapsed"
}

# -- Large banner ----------------------------------------------------------
# param $1: image name
# param $2: current index (1-based)
# param $3: total
function print_build_banner {
    local img="$1" idx="$2" tot="$3"
    local completed=$((idx - 1))
    print_box_banner \
        "BUILDING IMAGE ${idx} OF ${tot}" \
        "" \
        "Image : ${img}" \
        "Time  : $(date '+%Y-%m-%d %H:%M:%S')" \
        "Done  : ${completed}/${tot} completed"
    progress_bar "${completed}" "$tot"
}

# ============================================================================
# PHASE 2: BUILD -- iterate over discovered images with progress tracking
# ============================================================================
BUILD_START_EPOCH=$(date +%s)
count=0
errors=()
for docker_dir in "${CHANGED_DOCKER_DIRS[@]}"; do
    count=$((count + 1))
    image_name_short=$(basename "${docker_dir}")
    section_id="docker_build_${image_name_short//[^a-zA-Z0-9_]/_}"

    # -- Banner --
    print_build_banner "${image_name_short}" "${count}" "${total}"

    # -- GitLab collapsed section --
    gitlab_section_start "${section_id}" "[${count}/${total}] Building ${image_name_short}"

    # Run docker_build in the main shell (not a subshell pipe) so that
    # variable changes (PUSHED_DOCKERS, FAILED_DOCKERS, errors, etc.) are preserved.
    # We use process substitution to stream output through log_prefix in real-time
    # while keeping docker_build in the current shell.
    if [ "${UPLOAD_MODE}" = "true" ]; then
        # In upload mode, don't let a single image failure stop the entire build
        set +e
        docker_build "${docker_dir}" > >(log_prefix "${image_name_short}" "${count}" "${total}" "${max_name_len}" "${count_width}") 2>&1
        build_rc=$?
        set -e
        # Small delay to let the background log_prefix process flush
        wait 2>/dev/null || true
        if [ "$build_rc" -ne 0 ]; then
            record_failure "${image_name_short}" "build" "docker_build function returned non-zero exit code ${build_rc}"
        fi
    else
        set +e
        docker_build "${docker_dir}" > >(log_prefix "${image_name_short}" "${count}" "${total}" "${max_name_len}" "${count_width}") 2>&1
        build_rc=$?
        set -e
        wait 2>/dev/null || true
        if [ "$build_rc" -ne 0 ]; then
            exit "$build_rc"
        fi
    fi
    cd "${CURRENT_DIR}"

    # -- Close GitLab section --
    gitlab_section_end "${section_id}"

    # Track succeeded images (those that didn't fail)
    if [ "$build_rc" -eq 0 ]; then
        SUCCEEDED_IMAGES+=("${image_name_short}")
    fi

    echo ""
    echo "$(date '+%Y-%m-%d %H:%M:%S') Done building ${image_name_short} (${count}/${total})"
done

# Final progress
if [ "${total}" -gt 0 ]; then
    progress_bar "${total}" "${total}"
fi

# ============================================================================
# BUILD SUMMARY -- show what succeeded and what failed
# ============================================================================
BUILD_END_EPOCH=$(date +%s)
BUILD_DURATION=$((BUILD_END_EPOCH - BUILD_START_EPOCH))
BUILD_DURATION_FMT=$(printf '%02d:%02d:%02d' $((BUILD_DURATION/3600)) $(( (BUILD_DURATION%3600)/60 )) $((BUILD_DURATION%60)))

succeeded_count=${#SUCCEEDED_IMAGES[@]}
failed_count=${#FAILED_DOCKERS[@]}

# Determine pushed/artifacts status for summary
if [ -n "$PUSHED_DOCKERS" ]; then
    _pushed_status="Yes (${PUSHED_DOCKERS})"
    echo "${PUSHED_DOCKERS}" > "${ARTIFACTS_FOLDER}/pushed_dockers.txt"
else
    _pushed_status="None"
fi
if [ -n "${IMAGE_ARTIFACTS}" ]; then
    _artifacts_status="Yes (${IMAGE_ARTIFACTS})"
    echo "${IMAGE_ARTIFACTS}" > "${ARTIFACTS_FOLDER}/image_artifacts.txt"
else
    _artifacts_status="None"
fi

print_box_banner \
    "BUILD SUMMARY" \
    "" \
    "Total images : ${total}" \
    "Succeeded    : ${succeeded_count}" \
    "Failed       : ${failed_count}" \
    "Duration     : ${BUILD_DURATION_FMT}" \
    "Finished at  : $(date '+%Y-%m-%d %H:%M:%S')" \
    "" \
    "Pushed       : ${_pushed_status}" \
    "Artifacts    : ${_artifacts_status}"

# -- Succeeded images --
if [ "${succeeded_count}" -gt 0 ]; then
    echo ""
    print_sub_separator "-"
    echo "  SUCCEEDED IMAGES (${succeeded_count})"
    print_sub_separator "-"
    for img in "${SUCCEEDED_IMAGES[@]}"; do
        echo "    [OK] ${img}"
    done
fi

# -- Failed images with reasons --
if [ "${failed_count}" -gt 0 ]; then
    echo ""
    print_sub_separator "-"
    red_error "  FAILED IMAGES (${failed_count})"
    print_sub_separator "-"
    for img in "${!FAILED_DOCKERS[@]}"; do
        red_error "    [FAIL] ${img} -- step: ${FAILED_DOCKERS[$img]}"
    done
fi

# -- Version verification errors --
if [ ${#errors[@]} != 0 ]; then
    echo ""
    print_sub_separator "-"
    red_error "  VERSION VERIFICATION ERRORS (${#errors[@]})"
    print_sub_separator "-"
    for err in "${errors[@]}"; do
        red_error "    ${err}"
    done
fi

print_separator "="

# Write the failed dockers JSON report (always, even if empty)
if [ "${UPLOAD_MODE}" = "true" ]; then
    write_failed_dockers_report
fi

# Exit with error if there were failures in non-upload mode
if [ ${#errors[@]} != 0 ] && [ "${UPLOAD_MODE}" != "true" ]; then
    exit 1
fi
