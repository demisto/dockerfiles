#!/usr/bin/env bash

# exit on errors
set -e

#
# Will go over all Dockerfiles that have a comment of the form: 
# Last modified: <date>
# and change the <date> value to current utc time
#
# The "Last modified: ..." comment should be added to Dockerfiles which rely on 
# base images that are updated and their tags remain the same (for example the docker official python images)
#
# By updating the comment the circleci will see a modification and run again.
#

SCRIPT_DIR=$(dirname ${BASH_SOURCE})

find ${SCRIPT_DIR} -name Dockerfile | xargs sed -i "" -e "s/#[[:space:]]* Last modified:.*/# Last modified: $(date -R -u)/g"
