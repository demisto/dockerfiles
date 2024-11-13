#!/usr/bin/env bash

# exit on errors
set -e

###########################
# Script to download relevant chromedriver according to installed chrome version
###########################

# for testing pruposes (outside of the container) you can set GOOGLE_CHROME_VERSION env var
# for example: 
# docker run --rm -it -v `pwd`:/work -w /work -e GOOGLE_CHROME_VERSION=91.0.4472 demisto/chromium:1.0.0.23161 docker/chromium/download_chromedriver.sh

echo "url to download chromedriver version 126.0.6478.126"

curl https://storage.googleapis.com/chrome-for-testing-public/126.0.6478.126/linux64/chromedriver-linux64.zip --output chromedriver-linux64.zip
