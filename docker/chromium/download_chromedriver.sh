#!/usr/bin/env bash

# exit on errors
set -e

###########################
# Script to download relevant chromedriver according to installed chrome version
###########################

# for testing pruposes (outside of the container) you can set GOOGLE_CHROME_VERSION env var
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

echo "Finding chromedriver for given google-chrome version: $GOOGLE_CHROME_VERSION"


chromedriver=$(curl https://googlechromelabs.github.io/chrome-for-testing/latest-patch-versions-per-build-with-downloads.json | jq .builds.\"$GOOGLE_CHROME_VERSION\")
DRIVER_VERSION=$(echo $chromedriver | jq .version)

echo  "Using chromedriver version: $DRIVER_VERSION"

url=$(echo $chromedriver | jq -r '.downloads.chromedriver[] | select(.platform == "linux64") | .url')
echo "url to download chromedriver is $url"
wget $url

