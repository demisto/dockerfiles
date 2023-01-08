
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

### What should I do when changing a docker-image that is supported in the native image?
1) Check if the docker image that was changed is supported also in the native image. It is possible to check it in the [docker native image configuration file](https://github.com/demisto/content/blob/master/Tests/docker_native_image_config.json). **Note:** if you have changed a docker-image that is supported in the native image the **native docker validator workflow** will fail and alert you. 
2) If the docker image is supported by the native image, apply the same changes to the native image by the following scenarios:
   - If a new python dependency was added to the docker image, make sure it's also added to the native image, examples:  
      - assuming "pan-os-python" python module was added to the **[pan-os-python](https://github.com/demisto/dockerfiles/tree/master/docker/pan-os-python)** docker image, make sure to add the "pan-os-python" module library also to the native image.
      - assuming "beautifulsoup4" python module was added to the **[py3ews](https://github.com/demisto/dockerfiles/tree/master/docker/py3ews)** docker image, make sure to add the "beautifulsoup4" python module also to the native image.
   - If a new OS dependency was added to the docker image, make sure it's also added to the native image and also documented in **this** readme, examples:
      - assuming "git" was added to the **[crypto](https://github.com/demisto/dockerfiles/tree/master/docker/crypto)** docker image, make sure it is also added to the native image and make sure its documented [here](https://github.com/demisto/dockerfiles/blob/master/docker/py3-native/README.md#os-dependencies-for-each-custom-image).
      - assuming "curl" was added to the **[readpdf](https://github.com/demisto/dockerfiles/tree/master/docker/readpdf)** docker image, make sure it is also added to the native image and make sure its documented [here](https://github.com/demisto/dockerfiles/blob/master/docker/py3-native/README.md#os-dependencies-for-each-custom-image).
3) After you are done, add to your PR the label "native image approved" that means that the native image is compatible with the updated docker image that you changed.
4) **Add the script/integration to be ignored only in the production native images in the [docker native image configuration file](https://github.com/demisto/content/blob/master/Tests/docker_native_image_config.json), that will make the script/integration to run on the original docker image in XSOAR-NG.**
 

### What should I do when lint/test-playbook fails on the one of the native images?
* Add the script/integration to be ignored only in the problematic native image(s) in the [docker native image configuration file](https://github.com/demisto/content/blob/master/Tests/docker_native_image_config.json) under the `ignored_content_items` section, that will make the script/integration to run on the original docker image in XSOAR-NG.**
  - add the ID of the integration/script.
  - add the reason that this integration/script fails on the native-image(s).
  - add which native images should be ignored.
  - Full example: UnzipFile script that should not run on native-image 8.1 because there is a unit-test that fails along with that native image.
  ```
  {
    "id":"UnzipFile",
    "reason":"Failed unit-test: test_unrar_no_password",
    "ignored_native_images":[
        "native:8.1"
    ]
  }
  ```

### Optional Reading: Debugging failures/issues with native images in lint / test-playbooks
1) Check if lint / test-playbook has passed on the original docker image.
   - In case lint / test-playbook also failed on the original docker image:
     - The integration / script is not able to run on any docker image (original or native-image).
   - In case lint / test-playbook passed on the original docker image:
     - Create a terminal in the original docker image, Run: `docker run -it --rm <original_docker_image_tag> sh`
     - Create another terminal in the native image, Run: `docker run -it --rm <native_image_docker_tag> sh`.
2) After creating the terminals above, start debugging it based on the error, **common** scenarios: 
   - The lint/test-playbooks that run on the native-image(s) fail on import errors for a specific python module.
     - Run on both terminals `pip list | grep <python_module>` and check if the native-image is missing the dependency that the original docker image has, examples:
       - in docker image **[crypto](https://github.com/demisto/dockerfiles/tree/master/docker/crypto)** the *cryptography* python module is installed, while in the native image the *cryptography* python module is not installed at all. 
       - in docker image **[readpdf](https://github.com/demisto/dockerfiles/tree/master/docker/readpdf)** the *pypdf2* python module is installed, while in the native image the *pypdf2* python module is not installed at all.
   - The original docker image uses python module with version A and the native image uses the same python module with version B that causes native image to fail.
     - Run on both terminals `pip list | grep <python_module>` and compare the versions, if the versions are different make sure to install the same version on the native image if possible, examples:
       - in docker image **[crypto](https://github.com/demisto/dockerfiles/tree/master/docker/crypto)** the *cryptography* python module is installed with version 39.0.0, while in the native image the *cryptography* python module is installed with version 38.0.0.
       - in docker image **[readpdf](https://github.com/demisto/dockerfiles/tree/master/docker/readpdf)** the *pypdf2* python module is installed with version 2.0.1, while in the native image the *pypdf2* python module is installed with version 3.0.1.
   - Specific unit-test(s) fail when running lint on the native image on integrations/scripts that run shell commands which are based on installed OS dependencies.
     - On both terminals try to run the shell command and compare the results, in addition make sure the OS dependency versions are the same between the original docker image to the native image, example:
       - Given the script *UnzipFile* that uses *7z* OS dependency, run inside the terminals the same shell command that is being run in the unit-test, for example: `7z x -o<out_put_dir> <file_path.zip>`, or to check that versions aligned between the original docker image to the native image run `7z`
3) **If the issue cannot be resolved, refer to the [What should I do when lint/test-playbook fails on the one of the native images?](#what-should-i-do-when-linttest-playbook-fails-on-the-one-of-the-native-images) section.
4) **Note:** There could be more complicated scenarios involved here, The scenarios above are only **common** scenarios.

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

## Good To Know
* The packages that are being removed by `dnf remove` at the end are packages that are required **only** during the installation of python dependencies, once the python packages are installed they can be removed.

## References
* [docker native image configuration file](https://github.com/demisto/content/blob/master/Tests/docker_native_image_config.json)
* [The native image approved label](https://github.com/demisto/dockerfiles#the-native-image-docker-validator-and-native-image-approved-label)