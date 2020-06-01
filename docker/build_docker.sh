#!/usr/bin/env bash

# exit on errors
set -e

REVISION=${CIRCLE_BUILD_NUM:-`date +%s`}
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
        echo "Failed docker login for user: ${CR_USER}"
        return 2; 
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
        git status --short
        git pull
        echo "starting commit loop..."
        git add .
        git commit -m "`date`: trust update from PR: ${CIRCLE_PULL_REQUEST}"
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
    del_requirements=no
    if [ -f "Pipfile" -a ! -f "requirements.txt" ]; then
        if [ ! -f "Pipfile.lock" ]; then
            echo "Error: Pipfile present without Pipfile.lock. Make sure to commit your Pipfile.lock file"
            return 1
        fi
        pipenv --rm || echo "Proceeding. It is ok that no virtualenv is available to remove"
        PIPENV_YES=yes pipenv lock -r > requirements.txt
        echo "Pipfile lock generated requirements.txt: "
        cat requirements.txt
        del_requirements=yes
    fi
    tmp_dockerfile=$(mktemp)
    cp Dockerfile "$tmp_dockerfile"
    echo "" >> "$tmp_dockerfile"
    echo "ENV DOCKER_IMAGE=$image_full_name" >> "$tmp_dockerfile"
    docker build -f "$tmp_dockerfile" . -t ${image_full_name} \
        --label "org.opencontainers.image.authors=Demisto <containers@demisto.com>" \
        --label "org.opencontainers.image.version=${VERSION}" \
        --label "org.opencontainers.image.revision=${CIRCLE_SHA1}"
    rm "$tmp_dockerfile"
    if [ ${del_requirements} = "yes" ]; then
        rm requirements.txt
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
    if [ -f "verify.py" ]; then
        echo "==========================="            
        echo "Verifying docker image by running the python script verify.py within the docker image"
        cat verify.py | docker run --rm -i ${image_full_name} python '-'
    fi
    docker_trust=0
    if sign_setup; then
        docker_trust=1
        echo "using DOCKER_TRUST=${docker_trust} DOCKER_CONFIG=${DOCKER_CONFIG}"
    fi
    if docker_login; then
        env DOCKER_CONTENT_TRUST=$docker_trust DOCKER_CONFIG="${DOCKER_CONFIG}"  docker push ${image_full_name}
        echo "Done docker push for: ${image_full_name}"
        if [[ "$docker_trust" == "1" ]]; then
            commit_dockerfiles_trust
        fi
        ${DOCKER_SRC_DIR}/post_github_comment.py ${image_full_name}        
    else
        echo "Skipping docker push"
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
https://${REVISION}-161347705-gh.circle-artifacts.com/0/docker_images/$IMAGENAMESAVE.gz

Load it locally into docker by running:

\`\`\`
curl -L "https://${REVISION}-161347705-gh.circle-artifacts.com/0/docker_images/$IMAGENAMESAVE.gz" | gunzip | docker load
\`\`\`

--------------------------
EOF
        fi
    fi
    

    if [ -n "$CR_REPO" ] && cr_login; then
        docker tag ${image_full_name} ${CR_REPO}/${image_full_name}
        docker push ${CR_REPO}/${image_full_name} > /dev/null
        echo "Done docker push for cr: ${image_full_name}"
    else
        echo "Skipping docker push for cr"
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
            exit 1
        fi
    fi
    DOCKER_ORG=demisto
fi

echo "DOCKER_ORG: ${DOCKER_ORG}, DIFF_COMPARE: [${DIFF_COMPARE}], SCRIPT_DIR: [${SCRIPT_DIR}], CIRCLE_BRANCH: ${CIRCLE_BRANCH}, PWD: [${CURRENT_DIR}]"
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
