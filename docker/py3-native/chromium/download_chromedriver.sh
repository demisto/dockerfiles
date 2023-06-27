#!/usr/bin/env bash

# exit on errors
set -e

###########################
# Script to download relevant chromedriver according to installed chrome version
###########################

# for testing purposes (outside of the container) you can set GOOGLE_CHROME_VERSION env var
# for example: 
# docker run --rm -it -v `pwd`:/work -w /work -e GOOGLE_CHROME_VERSION=91.0.4472 demisto/chromium:1.0.0.23161 docker/chromium/download_chromedriver.sh
if [ -z "$GOOGLE_CHROME_VERSION" ]; then
    echo "Determing chrome version..."
    GOOGLE_CHROME_VERSION=$(google-chrome --version | grep -o -P '\d+\.\d+\.\d+')
fi

if [ -z "$GOOGLE_CHROME_VERSION" ]; then
    echo "something went wrong with getting chrome version. Aborting!!!"
    exit 1
fi 

echo "using GOOGLE_CHROME_VERSION: $GOOGLE_CHROME_VERSION"

echo "downloading chromedriver list..."
wget -O chromedriver.list.xml  https://chromedriver.storage.googleapis.com/ 

DRIVER_VERSION=$(grep -o -P "$GOOGLE_CHROME_VERSION\.\d+/chromedriver_linux64.zip" chromedriver.list.xml | sort -V | tail -1 | awk -F '/' '{print $1}')

echo  "Using chromedriver version: $DRIVER_VERSION"

wget https://chromedriver.storage.googleapis.com/${DRIVER_VERSION}/chromedriver_linux64.zip

if [ -z "$NO_CHROMEDRIVER_LIST_DELETE" ]; then
    rm chromedriver.list.xml
fi
