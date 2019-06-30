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
# Will update only docker/python* images. If you want somethign else set GREP_FILTER. 
# For example (will update only powershell* images):
#
# GREP_FILTER=docker/powershell ./dockerfiles_update_date.sh
#
#

SCRIPT_DIR=$(dirname ${BASH_SOURCE})

GREP_FILTER=${GREP_FILTER:-"docker/python"}

find ${SCRIPT_DIR} -name Dockerfile | grep -E "$GREP_FILTER" | xargs sed -i "" -e "s/#[[:space:]]* Last modified:.*/# Last modified: $(date -R -u)/g"
