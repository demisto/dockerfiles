
# Introduction
This README purpose is to clarify the following:
* Which docker images the native image supports
* The purpose of the **verifiers** folder
* OS dependencies for each docker image that the native image supports
* What are native images and how to handle them


## How To Handle Native Images
### What is a native image?
* Native image is a combination of a lot of docker images that scripts and integrations use. 
* The native image contains all the OS / python dependancies that are used in the supported docker images
* For example, given the docker image taxii2, tesseract and chromium, the native image will contain all of their OS / python dependencies. 
* That means that every integration/script that uses taxii2, tesseract or chromium docker image can also be used in the native image and there is compatibility between them.

### What should I do when changing a docker-image in the dockerfiles repo?
* Check if the docker image that was changed is supported also in the native image. It is possible to check it in the [docker native image configuration file]((https://github.com/demisto/content/blob/master/Tests/docker_native_image_config.json)). Note: if you have changed a docker-image that is supported in the native image the native docker validator workflow will fail and alert you. 
* If the docker image is supported by the native image, apply the same changes to the native image.
* If a new python dependency was added to the docker image, make sure it's also added to the native image.  
* If a new OS dependency was added to the docker image, make sure it's also added to the native image.
* After you are done, add to your PR the label "native image approved" that means that the native image is compatible with the updated docker image that you changed. 
* If the issue cannot be resolved, add the script/integration to be ignored in the [docker native image configuration file]((https://github.com/demisto/content/blob/master/Tests/docker_native_image_config.json)) with the native image version that failed, that will make the script/integration to run on the original docker image in XSOAR-NG. 

### What should I do when lint/test-playbook fails on the one of the native images?
* Check if lint / test-playbook has passed on the original docker image.
* In case yes, try to figure out what are the possible differences that can be between the original docker image to the native image version that failed.
* To create a terminal in the native image, Run: `docker run -it --rm <native_image_docker> sh`.
* Based on the error that the native image failed, try to understand what could be missing in the native image. For example if it's a possible python dependency issue, Run: *pip list* inside the docker of the native-image / original docker image and see if there is incompatibility between the version of the problematic python package.  
* The most common case will be that you miss a python dependency in the native image / the original docker image uses python module A version XXX and the native image uses python module A version YYY which might contain some significant changes between those two versions.
* If the issue cannot be resolved, add the script/integration to be ignored in the docker native image configuration file with the native image version that failed, that will make the script/integration to run on the original docker image in XSOAR-NG. 

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
* The packages that are being removed by `dnf remove` at the end are packages that are required **only** during the installation of python dependencies, once the python packages are installed they can be removed.

## References
* [docker native image configuration file](https://github.com/demisto/content/blob/master/Tests/docker_native_image_config.json)
* [The native image approved label](https://github.com/demisto/dockerfiles#the-native-image-docker-validator-and-native-image-approved-label)