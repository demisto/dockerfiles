#!/usr/bin/env bash

# exit on errors
set -e

REVISION=${CIRCLE_BUILD_NUM:-`date +%s`}

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
    current_dir=`pwd`
    cd $1
    image_name=$(basename ${docker_dir})
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
    VERSION=1.0.0
    if [ -f version ]; then
        VERSION=$(cat version | head -1)
    fi
    VERSION="${VERSION}.${REVISION}"
    echo "using version: ${VERSION}"
    docker build . -t ${DOCKER_ORG}/${image_name}:${CIRCLE_SHA1} \
        --label "maintainer=Demisto <containers@demisto.com>" \
        --label "version=${VERSION}"
    if [ ${del_requirements} = "yes" ]; then
        rm requirements.txt
    fi
    docker tag ${DOCKER_ORG}/${image_name}:${CIRCLE_SHA1} ${DOCKER_ORG}/${image_name}:${VERSION}
    if docker_login; then
        docker push ${DOCKER_ORG}/${image_name}:${CIRCLE_SHA1}
        docker push ${DOCKER_ORG}/${image_name}:${VERSION}
    fi
    cd ${current_dir}
}

if [ -z "$CIRCLE_SHA1" ]; then
    echo "CIRCLE_SHA1 not set. Assuming local testing."
    CIRCLE_SHA1=testing
    DOCKER_ORG=${DOCKER_ORG:-devtesting}    
fi

# default compare against master
DIFF_COMPARE=origin/master

if [[ ! $(which pyenv) ]]; then 
    echo "pyenv not found. sourcing bashrc to enable";\
    . ~/.bashrc
fi

echo "python version: "
python --version
env | grep -v DOCKERHUB
echo "pyenv versions:"
pyenv versions

if [ "$CIRCLE_BRANCH" == "master" ]; then
    # on master we use the range obtained from CIRCLE_COMPARE_URL
    # example of comapre url: https://github.com/demisto/content/compare/62f0bd03be73...1451bf0f3c2a
    DIFF_COMPARE=$(echo "$CIRCLE_COMPARE_URL" | sed 's:^.*/compare/::g')
    if [ -z "${DIFF_COMPARE}" ]; then
        echo "Failed: extracting diff compare from CIRCLE_COMPARE_URL: ${CIRCLE_COMPARE_URL}"
        exit 1
    fi
    #DOCKER_ORG=demisto # TODO: once approved we change this to demisto
fi

SCRIPT_DIR=$(dirname ${BASH_SOURCE})

for docker_dir in `find $SCRIPT_DIR -maxdepth 1 -mindepth 1 -type  d -print | sort`; do
    if [[ $(git diff $DIFF_COMPARE ${docker_dir}) ]]; then
        if [ -n "${DOCKER_INCLUDE_GREP}" ] && [ -z "$(echo ${docker_dir} | grep -E ${DOCKER_INCLUDE_GREP})" ]; then
            echo "Skipping dir: '${docker_dir}' as not included in grep expression DOCKER_INCLUDE_GREP: '${DOCKER_INCLUDE_GREP}'"
            continue
        fi
        echo "=============== `date`: Starting docker build in dir: ${docker_dir} ==============="
        docker_build ${docker_dir}
        echo ">>>>>>>>>>>>>>> `date`: Done docker build <<<<<<<<<<<<<"
    fi
done
