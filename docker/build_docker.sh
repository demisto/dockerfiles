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

DOCKER_LOGIN_DONE=no
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
    docker build . -t ${DOCKER_ORG}/${image_name}:${CIRCLE_SHA1} \
        --label "org.opencontainers.image.authors=Demisto <containers@demisto.com>" \
        --label "org.opencontainers.image.version=${VERSION}" \
        --label "org.opencontainers.image.revision=${CIRCLE_SHA1}"
    if [ ${del_requirements} = "yes" ]; then
        rm requirements.txt
    fi
    docker tag ${DOCKER_ORG}/${image_name}:${CIRCLE_SHA1} ${DOCKER_ORG}/${image_name}:${VERSION}
    if [[ "$(prop 'devonly')" ]]; then
        echo "Skipping license verification for devonly image"
    else
        ${DOCKER_SRC_DIR}/verify_licenses.py ${DOCKER_ORG}/${image_name}:${VERSION}
    fi
    if docker_login; then
        docker push ${DOCKER_ORG}/${image_name}:${CIRCLE_SHA1}
        docker push ${DOCKER_ORG}/${image_name}:${VERSION}
        ${DOCKER_SRC_DIR}/post_github_comment.py ${DOCKER_ORG}/${image_name}:${VERSION}
    fi    
}

if [ -z "$CIRCLE_SHA1" ]; then
    echo "CIRCLE_SHA1 not set. Assuming local testing."
    CIRCLE_SHA1=testing
    DOCKER_ORG=${DOCKER_ORG:-devtesting}    
fi

# default compare against master
DIFF_COMPARE=origin/master

if [[ ! $(which pyenv) ]]; then 
    echo "pyenv not found. setting up necessary env for pyenv";\
    export PATH="$HOME/.pyenv/bin:$PATH"
    eval "$(pyenv init -)"
    eval "$(pyenv virtualenv-init -)"
fi

echo "python version: "
python --version
echo "pyenv versions:"
pyenv versions

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
        echo "CIRCLE_COMPARE_URL not set. Assuming no successful build yet and setting DIFF to ALL."
        DIFF_COMPARE="ALL"
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

for docker_dir in `find $SCRIPT_DIR -maxdepth 1 -mindepth 1 -type  d -print | sort`; do
    if [[ ${DIFF_COMPARE} = "ALL" ]] || [[ $(git diff $DIFF_COMPARE -- ${docker_dir}) ]]; then
        if [ -n "${DOCKER_INCLUDE_GREP}" ] && [ -z "$(echo ${docker_dir} | grep -E ${DOCKER_INCLUDE_GREP})" ]; then
            [[ -z "$1" ]] && echo "Skipping dir: '${docker_dir}' as not included in grep expression DOCKER_INCLUDE_GREP: '${DOCKER_INCLUDE_GREP}'"
            continue
        fi
        echo "=============== `date`: Starting docker build in dir: ${docker_dir} ==============="
        docker_build ${docker_dir}
        cd ${CURRENT_DIR}
        echo ">>>>>>>>>>>>>>> `date`: Done docker build <<<<<<<<<<<<<"
    fi
done
