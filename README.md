# Demisto's Dockerfiles and Image Build Management

[![CircleCI](https://circleci.com/gh/demisto/dockerfiles.svg?style=svg)](https://circleci.com/gh/demisto/dockerfiles)

This repository's `master` branch tracks images pushed to the official Demisto Docker Hub organization at: https://hub.docker.com/u/demisto/. Other branches` images are pushed to [devdemisto](https://hub.docker.com/u/devdemisto).

**Note:** We generate nightly information about packages and os dependencies used in each of Demisto's docker images. Checkout the `dockerfiles-info` project [README](https://github.com/demisto/dockerfiles-info/blob/master/README.md) for a full listing.

## Contributing
Contributions are welcome and appreciated. To contribute follow the [Getting Started](#getting-started) section and submit a PR. 

In order to conntribute, we will need all contributors to sign a contributor license agreement. By signing a contributor license agreement, we ensure that the community is free to use your contributions.

When opening a new pull request, a bot will evaluate whether you have signed the CLA. If required, the bot will comment on the pull request, including a link to accept the agreement. The CLA document is also available for review as a [PDF](https://github.com/demisto/content/blob/master/docs/cla.pdf).
Visit our [Frequently Asked Questions](https://xsoar.pan.dev/docs/concepts/faq#cla-is-pending-even-though-i-signed-the-agreement) article for CLA related issues.

After opening your docker pull request, and in order for the reviewer to understand the context, make sure to link to the corresponding pull request from the [Content](https://github.com/demisto/content) repo where this docker image will be used.
## Getting Started
Each docker image is managed in its own directory. The directory should be named the same as the image name (without the organization prefix). If needed, we prefer using a dash (`-`) as a separator in the name. All image directories are located under the `docker` dir.

The directory should contain one Dockerfile which will be used for building the docker image. Each image when it is built is tagged with the commit hash and version. 

The script `docker/build_docker.sh` is used to build all modified docker images. The script detects modified directories by comparing against origin/master if on a branch or if on master by using the CIRCLE_COMPARE_URL environment variable to obtain the commit range of the current build.

**Pre-requisites:**
* Install python 2 and 3 (so you can create both python 2 and 3 images):
  * Mac: use brew to install (more info at: https://docs.brew.sh/Homebrew-and-Python): `brew install python3` and then: `brew install python@2`
* Or install pyenv (recommended for managing multiple python versions):
    * Mac: `brew install pyenv` . Make sure to run then: `pyenv init` and follow instructions to add to either `~/.zshrc` or `~/.bash_profile` depending on you shell.
    * Other: see https://github.com/pyenv/pyenv-installer 
* Install pipenv globally using: `pip install pipenv`
* Install requests globally: `pip install requests`

To get up and running fast with a Python/PowerShell image with additional packages use the script: `docker/create_new_docker_image.py`. Usage:
```
usage: create_new_docker_image.py [-h] [-t {python,powershell}]
                                  [-p {two,three}] [-l {alpine,debian,ubuntu}]
                                  [--pkg PKG]
                                  name

Create a new docker image

positional arguments:
  name                  The image name to use without the organization prefix.
                        For example: ldap3. We use kebab-case naming
                        convention.

optional arguments:
  -h, --help            show this help message and exit
  -t {python,powershell}, --type {python,powershell}
                        Specify type of image to create (default: python)
  -p {two,three}, --python {two,three}
                        Specify python version to use (default: three)
  -l {alpine,debian,ubuntu}, --linux {alpine,debian,ubuntu}
                        Specify linux distro to use (default: alpine)
  --pkg PKG             Specify a package/module to install. Can be specified
                        multiple times. Each package needs to be specified
                        with --pkg. For example: --pkg google-cloud-storage
                        --pkg oath2client (default: None)
```

For example to create a new image named ldap using python 3 and with the python package ldap3 run the following:
```
./docker/create_new_docker_image.py -p three --pkg ldap3 ldap
```
The above command will create a directory `docker/ldap` with all relevant files all setup for building a docker image. You can now build the image locally by following: [Building Locally a Test Build](#building-locally-a-test-build).

**Note:** for image names we use [kebab-case](https://www.theserverside.com/definition/Kebab-case) naming convention.

## Building a docker image locally
It is possible to run a local build to verify that the build process is working. Requirements:
* Local install of docker
* Local install of pipenv or poetry (if building an image which is managing packages via these build tools - recommended)


If you want to test how the script detects commit changes: Make sure you are working on a branch and the changes are committed. If you haven't committed the changes and want to run a local build you can run the script with a image name (which corresponds to a directory name) to the run the build on. For example:

```
./docker/build_docker.sh ldap
```

The above example will then run the build against the `ldap` directory.

When running locally, the script will then use a docker organization of `devtesting` and will tag the image with a `testing` tag and a version which has a timestamp as a revision. If you would like to test with a different organization name set the env variable: DOCKER_ORG. If you would like to test the push functionality set the env variable DOCKERHUB_USER. It is also possible to set DOCKERHUB_PASSWORD to avoid being prompted for the password during the build process.

Additionally, if you are working on multiple folders and would like to test only a specific one the script supports an env var of DOCKER_INCLUDE_GREP which will be used to do an extended grep to choose which directories to process.

Example for running with an org name of mytest and a grep extended expression which will process only the `python` dir (and not `python3` dir):

```
DOCKER_ORG=mytest DOCKER_INCLUDE_GREP=/python$ docker/build_docker.sh 
``` 


## Build configuration
The build script will check for a `build.conf` file in the target image directory and will read from it `name=value` properties. Supported properties:

* **version**: The version to use for tagging. Default: `1.0.0`. See [Dynamic Versioning](#dynamic-versioning) for non-static versions. #Note: that additionally, the CircleCI build number is always appended to the version as a revision (for example: `1.0.0.15519`) to create a unique version per build.
* **devonly**: If set the image will be pushed only to the `devdemisto` org in docker hub and will not be pushed to the `demisto` org. Should be used for images which are for development purposes only (such as the image used in CircleCI to build this project).
* **deprecated**: If set the image will be listed as deprecated in the deprecated_images.json file and the image will be forbidden form using in the integrations/automations.
* **deprecated_reason**: Free text that explain the deprecation reason.

## Dynamic Versioning
It can be convenient to set the version of the docker image dynamically, instead of as an entry in build.conf.
For example, if the docker image is meant to track a particular package, the version of the image should always be the same as that package. Dependabot relocking the dependencies can cause the real package number and the entry in build.conf to fall out of sync.

As a solution to this, you can add a `dynamic_version.sh` file to the image's folder. This will be run in the built docker container, and the result will be used to set the image's version in dockerhub. See [here](https://github.com/demisto/dockerfiles/blob/master/docker/demisto-sdk/dynamic_version.sh) for an example.

## Base Python Images
There are 4 base python images which should be used when building a new image which is based upon python:

* [python](https://github.com/demisto/dockerfiles/blob/repository-info/demisto/python/last.md): Python 2 image based upon alpine
* [python3](https://github.com/demisto/dockerfiles/blob/repository-info/demisto/python3/last.md): Python 3 image based upon alpine
* [python-deb](https://github.com/demisto/dockerfiles/blob/repository-info/demisto/python-deb/last.md): Python 2 image based upon debian
* [python3-deb](https://github.com/demisto/dockerfiles/blob/repository-info/demisto/python3-deb/last.md): Python 3 image based upon debian

### Which image to choose as a base?

If you are using pure python dependencies then choose the alpine image with the proper python version which fits your needs (two or three). The alpine based images are smaller and recommended for use. If you require installing binaries or pre-compiled binary python dependencies ([manylinux](https://github.com/pypa/manylinux)), you are probably best choosing the debian based images. See the following link: https://github.com/docker-library/docs/issues/904 .

If you are using the python [cryptography](https://pypi.org/project/cryptography/) package we recommend using [demisto/crypto](https://github.com/demisto/dockerfiles/blob/repository-info/demisto/crypto/last.md) as a base image. This base image takes care of properly installing the `cryptography` package. There is no need to include the `cryptography` package in the Pipenv file when using this image as a base.

## Adding a `verify.py` script
As part of the build we support running a `verify.py` script in the created image. This allows you to add logic which tests and checks that the docker image built is matching what you expect. 

Adding this file is **highly** recommended.

Simply create a file named: `vefify.py`. It may contain any python code and all it needs is to exit with status 0 as a sign for success. Once the docker image is built, if the script is present it will be run within the image using the following command:
```bash
cat verify.py | docker run --rm -i <image_name> python '-'
```
Example of docker image with simple `verify.py` script can be seen [here](https://github.com/demisto/dockerfiles/tree/master/docker/m2crypto)

## PowerShell Images
We support building PowerShell Core docker images. To create the Dockerfile for a PowerShell image use the `docker/create_new_docker_image.py` script with the `-t` or `--type` argument set to: `powershell`. For example:

```
./docker/create_new_docker_image.py -t powershell --pkg Az pwsh-azure
```
The above command will create a directory `docker/pwsh-azure` with all relevant files setup for building a PowerShell docker image which imports the Az PowerShell module. You can now build the image locally by following: [Building Locally a Test Build](#building-locally-a-test-build).

**Naming Convention:** To differentiate PowerShell images, name the images with a prefix of either `pwsh-` or `powershell-`.

### Base PowerShell Images
There are 3 base PowerShell images which should be used when building a new image which is based upon PowerShell:

* [powershell](https://github.com/demisto/dockerfiles/blob/repository-info/demisto/powershell/last.md): PowerShell image based upon Alpine (default)
* [powershell-deb](https://github.com/demisto/dockerfiles/blob/repository-info/demisto/powershell-deb/last.md): PowerShell image based upon Debian
* [powershell-ubuntu](https://github.com/demisto/dockerfiles/blob/repository-info/demisto/powershell-ubuntu/last.md): PowerShell image based upon Ubuntu

We recommend using the default Alpine based image. The Debian and Ubuntu images are provided mainly for cases that there is need to install additional OS packages.

### Adding a `verify.ps1` script
Similar to the `verify.py` script for Python images, you can add a `verify.ps1` script to test and check the image you created. 

Once the docker image is built, if the script is present it will be run within the image using the following command:
```bash
cat verify.ps1 | docker run --rm -i <image_name> pwsh -c '-'
```

## Docker Image Deployment
When you first open a PR, a `development` docker image is built (via CircleCI) under the `devdemisto` docker organization. So for example if your image is named `ldap3` an image with the name `devdemisto/ldap3` will be built. 

If the PR is on a local branch of the `dockerfiles` github project (relevant only for members of the project with commit access), the image will be deployed to the [devdemisto](https://hub.docker.com/u/devdemisto) docker hub organization. A bot will add a comment to the PR stating that the image has been deployed and available. You can then test the image out simply by doing `docker pull <image_name>` (instructions will be included in the comment added to the PR).

If you are contributing (**thank you!!**) via an external fork, then the image built will not be deployed to docker hub. It will be available to download from the build artifacts. You can download the image and load it locally by running the `docker load` command. If you go into the build details in CircleCI you will see also instructions in the end of the `Build Docker Images` step on how to load it with a one liner bash command. Example contribution build can be seen [here](https://circleci.com/gh/demisto/dockerfiles/1976#artifacts/containers/0).

Once merged into master, CircleCI will run another build and create a `production` ready docker image which will be deployed at Docker Hub under the [demisto](https://hub.docker.com/u/demisto) organization. A bot will add a comment to the original PR about the production deployment and the image will then be fully available for usage. An example `production` comment added to a PR can be seen [here](https://github.com/demisto/dockerfiles/pull/462#issuecomment-533150059).

## Advanced

### Support for Pipenv (Pipfile) and Poetry (pyproject.toml)
It is recommended to use [Pipenv](https://pipenv.readthedocs.io/en/latest/) or [Poetry](https://python-poetry.org/docs/) to manage python dependencies as they ensure that the build produces a deterministic list of python dependencies.

If a `Pipfile` or `pyproject.toml` file is detected and a requirements.txt file is not present, the file will be used to generate a requirements.txt file before invoking `docker build`. The file is generated by running: `pipenv lock -r` for pipenv, or `poetry export -f requirements.txt --output requirements.txt --without-hashes` for poetry. This allows the build process in the Dockerfile to simply install python dependencies via: 
```docker
RUN pip install --no-cache-dir -r requirements.txt
``` 

If the requirements should'nt be generated before docker build, for example if you need system requirements installed in order to successfully install the dependencies, you can add **dont_generate_requirements=true** to the build.conf file, and the file will not be generated by the build.

**Note**: build will fail if a `Pipfile` is detected without a corresponding `Pipfile.lock` file or `pyproject.toml` file is found without a corresponding `poetry.lock`.

### Poetry quick start:
If you want to use poetry, make sure you have poetry installed by running `poetry --version` or install it by running`curl -sSL https://install.python-poetry.org | python3`. Then Follow:
* In the relevant folder initialize the poetry environment using `poetry init`.
* Install dependencies using: `poetry add <dependency>`. For example: `poetry add requests`
* Make sure to commit both `pyproject.toml` and `poetry.lock` files
* To see the locked dependencies run: `poetry export -f requirements.txt --output requirements.txt --without-hashes` 

### Pipenv quick start:
If you want to use pipenv manually make sure you first have the pre-requisites installed as specified in [Getting Started](#getting-started). Then follow:
* In the relevant folder initialize the pipenv environment:
    * python 2: `PIPENV_MAX_DEPTH=1 pipenv --two`
    * python 3: `PIPENV_MAX_DEPTH=1 pipenv --three`
* Install dependencies using: `pipenv install <dependency>`. For example: `pipenv install requests`
* Make sure to commit both `Pipfile` and `Pipfile.lock` files
* To see the locked dependencies run: `pipenv lock -r` 

### Installing a Common Dependency
If you want to install a new common dependency in all python base images use the script: `install_common_python_dep.sh`. Usage:
```
Usage: ./docker/install_common_python_dep.sh [packages]

Install a common python dependency in all docker python base images.
Will use pipenv to install the dependency in each directory.
Base images:
   python
   python3
   python-deb
   python3-deb

For example: ./docker/install_common_python_dep.sh dateparser
```
**Note:** By default pipenv will install the specified dependency and also update all other dependencies if possible. If you want to only install a dependency and not update the existing dependencies run the script with the env variable: `PIPENV_KEEP_OUTDATED`. For example:
```
PIPENV_KEEP_OUTDATED=true ./docker/install_common_python_dep.sh dateparser
```

### Automatic updates via Dependabot
We use [dependabot](https://docs.github.com/en/code-security/supply-chain-security/keeping-your-dependencies-updated-automatically) for automated dependency updates. When a new image is added to the repository there is need to add the proper config to [.github/dependabot.yml](.github/dependabot.yml). If you used the `./docker/create_new_python_image.py` to create the docker image, then this config will be added automatically by the script. Otherwise, you will need to add the proper dependabot config. The build will fail without this config. You can add the dependabot config by running the script:
```
./docker/add_dependabot.sh <folder path to new docker image>
```
For example:
```
./docker/add_dependabot.sh docker/nmap
```

### How to mark image as deprecated

To mark an image as deprecated please follow the following steps:

1. Add the following two keys to the build.conf of the image.

  * deprecated=true
  * deprecated_reason=free text

  (i.e.:
  version=1.0.0
  deprecated=true
  deprecated_reason="the image was merged into py3-tools")

* 2- Build the docker by running the docker/build_docker.sh
  * (i.e. /home/users/dockerfiles$ docker/build_docker.sh emoji)
  By running the build script the image information will be added to the deprecated_images.json and 2 new environment variables will be introduced in the docker :
  * DEPRECATED_IMAGE=true
  * DEPRECATED_REASON="the same text as deprecated_reason key from the build.conf file"
* 3- commit all chnaged files including the deprecated_image.json and create a new PR

### The Native Image Docker Validator and *native image approved* label

In the event that you've updated a native-image-supported dockerimage, you need to make sure that you take the necessary steps to ensure that native image is running smoothly in our build.
If such docker is being updated, then the validation will fail to alarm the user that the native docker might need updates according to the changes done to the supported updated docker.
For example, if you added a new package to the image, chances are you will need to add the same package to the native image.  
The user should Check if the native image is already compatible with this change. If it is, great. Otherwise, the user should add compatibility, and add the relevant integration to the ignore conf. as necessary.
After the required changes are done in this repository and in the content repository, the reviewer should add the 'native image approved' label which will re-trigger the workflow and pass the validation.