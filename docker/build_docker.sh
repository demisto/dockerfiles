#!/usr/bin/env bash

# exit on errors
set -e

REVISION=${CIRCLE_BUILD_NUM:-`date +%s`}
PUSHED_DOCKERS=''
CURRENT_DIR=`pwd`
SCRIPT_DIR=$(dirname ${BASH_SOURCE})
DOCKER_SRC_DIR=${SCRIPT_DIR}
if [[ "${DOCKER_SRC_DIR}" != /* ]]; then
    DOCKER_SRC_DIR="${CURRENT_DIR}/${SCRIPT_DIR}"
fi
DOCKERFILES_TRUST_DIR="${DOCKER_SRC_DIR}/../dockerfiles-trust"

# parse a propty form build.conf file in current dir
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
function sign_setup {
    if [ "${SIGN_SETUP_DONE}" = "yes" ]; then
        return 0;
    fi
    if [ -z "${DOCKER_CONTENT_TRUST_REPOSITORY_PASSPHRASE}" -o -z "${DOCKER_CONTENT_TRUST_ROOT_PASSPHRASE}" -o -z "${DOCKERFILES_TRUST_GIT}" ]; then
        echo "Content trust passphrases not set. Not setting up docker signing."
        return 1;
    fi
    if [ ! -d "${DOCKERFILES_TRUST_DIR}" ]; then
        git clone "${DOCKERFILES_TRUST_GIT}" "${DOCKERFILES_TRUST_DIR}"   
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
        git commit -m "$(date): trust update from PR: ${CIRCLE_PULL_REQUEST}"
        COMMIT_DONE=no
        for i in 1 2 3 4 5; do
            if git push; then
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
    if  [[ "$CIRCLE_BRANCH" == "master" ]] && [[ "$(prop 'devonly')" ]]; then
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
    if [ -f "Pipfile" -a ! -f "requirements.txt" ]; then
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

    if [ -f "pyproject.toml" -a ! -f "requirements.txt" ]; then
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
    
    docker build -f "$tmp_dir/Dockerfile" . -t ${image_full_name} \
        --label "org.opencontainers.image.authors=Demisto <containers@demisto.com>" \
        --label "org.opencontainers.image.version=${VERSION}" \
        --label "org.opencontainers.image.revision=${CIRCLE_SHA1}"

    if [[ -e "dynamic_version.sh" ]]; then
      echo "dynamic_version.sh file was found"
      dynamic_version=$(docker run --rm -i "$image_full_name" sh < dynamic_version.sh)
      echo "dynamic_version $dynamic_version"
      VERSION="${dynamic_version}.${REVISION}"
      image_full_name="${DOCKER_ORG}/${image_name}:${VERSION}"

      # add the last layer and rebuild. Everything shuld be cached besides this layer
      echo "ENV DOCKER_IMAGE=$image_full_name" >> "$tmp_dir/Dockerfile"

      echo "running docker build again with tag $image_full_name"

      docker build -f "$tmp_dir/Dockerfile" . -t ${image_full_name} \
        --label "org.opencontainers.image.authors=Demisto <containers@demisto.com>" \
        --label "org.opencontainers.image.version=${VERSION}" \
        --label "org.opencontainers.image.revision=${CIRCLE_SHA1}"
    fi
    rm -rf "$tmp_dir"

    if [ ${del_requirements} = "yes" ]; then
        rm requirements.txt
    fi
    if [ -n "$CI" ]; then
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
    
    if [[ "$(prop 'devonly')" ]]; then
        echo "Skipping license verification for devonly image"
    else
        PY3CMD="python3"
        if command -v python3.7 >/dev/null 2>&1; then
            PY3CMD="python3.7"
        elif command -v python3.8 >/dev/null 2>&1; then
            PY3CMD="python3.8"
        fi
        $PY3CMD ${DOCKER_SRC_DIR}/verify_licenses.py ${image_full_name}
    fi

    for filename in `find . -name "*verify.py"`; do
      echo "==========================="
      echo "Verifying docker image by running the python script $filename within the docker image"
      cat $filename | docker run --rm -i ${image_full_name} python '-'
    done

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

    if docker_login; then
        env DOCKER_CONTENT_TRUST=$docker_trust DOCKER_CONFIG="${DOCKER_CONFIG}"  docker push ${image_full_name}
        echo "Done docker push for: ${image_full_name}"
        PUSHED_DOCKERS="${image_full_name},$PUSHED_DOCKERS"
        echo "debug pushed_dockers $PUSHED_DOCKERS"
        if [[ "$docker_trust" == "1" ]]; then
            commit_dockerfiles_trust
        fi
        if ! ${DOCKER_SRC_DIR}/post_github_comment.py ${image_full_name}; then 
            echo "Failed post_github_comment.py. Will stop build only if not on master"
            if [ "$CIRCLE_BRANCH" == "master" ]; then
                echo "Continuing as we are on master branch..."
            else
                echo "failing build!!"
                exit 5
            fi
        fi
    else
        echo "Skipping docker push"
        if [ "$CIRCLE_BRANCH" == "master" ]; then
          echo "Did not push image on master. Failing build"
          exit 1
        fi
        if [ -n "$CI" ]; then
            echo "Creating artifact of docker image..."
            ARTDIR="${DOCKER_SRC_DIR}/../artifacts"
            mkdir -p "${ARTDIR}"
            IMAGENAMESAVE=`echo ${image_full_name} | tr / _`.tar
            IMAGESAVE=${ARTDIR}/$IMAGENAMESAVE
            docker save -o "$IMAGESAVE" ${image_full_name}
            gzip "$IMAGESAVE"
            cat << EOF
-------------------------

Docker image [$image_full_name] has been saved as an artifact. It is available at the following link: 
https://output.circle-artifacts.com/output/job/${CIRCLE_WORKFLOW_JOB_ID}/artifacts/0/docker_images/$IMAGENAMESAVE.gz

Load it locally into docker by running:

\`\`\`
curl -L "https://output.circle-artifacts.com/output/job/${CIRCLE_WORKFLOW_JOB_ID}/artifacts/0/docker_images/$IMAGENAMESAVE.gz" | gunzip | docker load
\`\`\`

--------------------------
EOF
        fi
    fi

}

# default compare circle branch against master
DIFF_COMPARE=origin/master...${CIRCLE_BRANCH}

if [ -z "$CIRCLE_SHA1" ]; then
    echo "CIRCLE_SHA1 not set. Assuming local testing."
    CIRCLE_SHA1=testing
    DOCKER_ORG=${DOCKER_ORG:-devtesting}
    
    if [ -z "$CIRCLE_BRANCH" ]; then
        # simply compare against origin/master
        DIFF_COMPARE=origin/master
    fi
fi


if [[ ! $(which pyenv) ]] && [[ -n "${CIRCLECI}" ]]; then 
    echo "pyenv not found. setting up necessary env for pyenv on circle ci";\
    export PATH="$HOME/.pyenv/bin:$PATH"
    eval "$(pyenv init -)"
    eval "$(pyenv virtualenv-init -)"
    pyenv shell system $(pyenv versions --bare | grep 3.7)
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

if [ "$CIRCLE_BRANCH" == "master" ]; then
    # on master we use the range obtained from CIRCLE_COMPARE_URL
    # example of comapre url: https://github.com/demisto/content/compare/62f0bd03be73...1451bf0f3c2a
    # if there wasn't a successful build CIRCLE_COMPARE_URL is empty. We set diff compare to special ALL
    if [ -z "$CIRCLE_COMPARE_URL" ]; then
        echo "CIRCLE_COMPARE_URL not set. Assuming 'rebuild'. Comparing last commit."
        DIFF_COMPARE="HEAD^1...HEAD"
    else
        DIFF_COMPARE=$(echo "$CIRCLE_COMPARE_URL" | sed 's:^.*/compare/::g')    
        if [ -z "${DIFF_COMPARE}" ]; then
            echo "Failed: extracting diff compare from CIRCLE_COMPARE_URL: ${CIRCLE_COMPARE_URL}"
            exit 2
        fi
    fi
    DOCKER_ORG=demisto
fi

echo "DOCKER_ORG: ${DOCKER_ORG}, DIFF_COMPARE: [${DIFF_COMPARE}], SCRIPT_DIR: [${SCRIPT_DIR}], CIRCLE_BRANCH: ${CIRCLE_BRANCH}, PWD: [${CURRENT_DIR}]"

# echo to bash env to be used in future steps
CIRCLE_ARTIFACTS="artifacts"
if [[ ! -d $CIRCLE_ARTIFACTS ]]; then
  mkdir $CIRCLE_ARTIFACTS
fi

echo $DIFF_COMPARE > $CIRCLE_ARTIFACTS/diff_compare.txt
echo $SCRIPT_DIR > $CIRCLE_ARTIFACTS/script_dir.txt
echo $CURRENT_DIR > $CIRCLE_ARTIFACTS/current_dir.txt
echo $DOCKER_INCLUDE_GREP > $CIRCLE_ARTIFACTS/docker_include_grep.txt

total=$(find $SCRIPT_DIR -maxdepth 1 -mindepth 1 -type  d -print | wc -l)
count=0
for docker_dir in `find $SCRIPT_DIR -maxdepth 1 -mindepth 1 -type  d -print | sort`; do
    if [[ ${DIFF_COMPARE} = "ALL" ]] || [[ $(git diff --name-status $DIFF_COMPARE -- ${docker_dir}) ]]; then
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
echo $PUSHED_DOCKERS > $CIRCLE_ARTIFACTS/pushed_dockers.txt
echo "Successfully pushed $PUSHED_DOCKERS"
