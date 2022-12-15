
# Introduction
This README purpose is to clarify the following:
* Which docker images the native image supports
* The purpose of the **verifiers** folder
* OS dependencies for each docker image that the native image supports.

## Supported Docker Images
* python3 
* python3-deb
* python3-ubi
* py3-tools
* py3-tools-ubi
* tesseract
* chromium
* crypto
* readpdf
* parse-emails
* docxpy
* sklearn
* pandas
* ippysocks-py3
* oauthlib
* unzip
* py3ews
* taxii2
* pan-os-python
* slackv3
* google-api-py3
* boto3py3
* pyjwt3
* joe-security
* slack
* office-utils


## Verifiers Folder
For each docker image that the native image supports, a symbolic link has been created to reference to original `verify.py` of that docker image.

That is done in order to keep updated with the python dependencies the original docker images that the native image supports. 


## OS Dependencies For Each Custom Image
* **tesseract:** git automake make autoconf libtool clang zlib zlib-devel libjpeg libjpeg-devel libwebp libwebp-devel libtiff libtiff-devel libpng libpng-devel pango giflib giflib-devel leptonica 
* **chromium:** python3-devel gcc gcc-c++ make wget git unzip llvm-libs libXpm tigervnc-server-minimal xorg-x11-utils google-chrome-stable ImageMagick
* **crypto:** python3-devel gcc gcc-c++ make wget git rust cargo libffi-devel openssl-devel
* **readpdf:** poppler poppler-utils
* **parse-emails:** libffi-devel, python3-devel, wget, git
* **docxpy:** libxml2-devel, libxslt-devel, python3-devel, wget
* **sklearn:** python3-devel gcc gcc-c++ make wget git openssh curl ca-certificates openssl less make rsync libpng-devel freetype-devel gcc-gfortran openblas unzip
* **pandas:** python3-devel gcc gcc-c++ make wget git libstdc++
* **ippysocks-py3:** gcc python3-devel
* **oauthlib:** python3-devel gcc gcc-c++ make wget git
* **unzip:** python3-devel gcc gcc-c++ make wget git p7zip unrar unrar-free
* **py3ews:** python3-devel gcc gcc-c++ make wget git libxml2-devel openssl-devel
* **taxii2:** python3-devel gcc gcc-c++ make wget git
* **pan-os-python:** python3-devel gcc gcc-c++ make wget git
* **slackv3:** python3-devel gcc gcc-c++ make wget git libffi-devel
* **google-api-py3:** python3-devel gcc
* **boto3py3:** python3-devel gcc gcc-c++ make wget git
* **pyjwt3:** python3-devel gcc gcc-c++ make wget git
* **joe-security:** python3-devel gcc gcc-c++ make wget git
* **slack:** python3-devel gcc gcc-c++ make wget git libffi
* **office-utils:** LibreOffice_Linux_x86-64_rpm java-11-openjdk-headless cairo libSM libX11-xcb

## Notes
The packages that are being removed by `dnf remove` at the end are packages that are required **only** during the installation of python dependencies, once the python packages are installed they can be removed.