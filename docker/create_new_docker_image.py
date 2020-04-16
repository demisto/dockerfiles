#!/usr/bin/env python

import argparse
import sys
import os
import requests
import datetime
import string
import shutil
import subprocess

DOCKER_PYTHON_ALPINE = '''
FROM {image}

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget git \\
  && pip install --no-cache-dir -r requirements.txt \\
  && apk del .build-dependencies
'''

DOCKER_PYTHON_DEBIAN = '''
FROM {image}

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \\
  gcc \\
  python-dev \\
&& pip install --no-cache-dir -r requirements.txt \\
&& apt-get purge -y --auto-remove \\
  gcc \\
  python-dev \\
&& rm -rf /var/lib/apt/lists/*
'''

DOCKER_POWERSHELL = '''
FROM {image}

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
RUN pwsh -c "Install-Module -ErrorAction Stop {modules}"
'''


def get_latest_tag(image_name):
    last_tag = None
    last_date = None
    url = "https://registry.hub.docker.com/v2/repositories/{}/tags/?page_size=25".format(image_name)
    while True:
        print("Querying docker hub url: {}".format(url))
        res = requests.get(url)
        res.raise_for_status()
        obj = res.json()
        for result in obj['results']:
            name = result['name']
            if len(name) >= 20 and all(c in string.hexdigits for c in name):  # skip git sha revisions
                continue
            date = datetime.datetime.strptime(result['last_updated'], "%Y-%m-%dT%H:%M:%S.%fZ")
            if not last_date or date > last_date:
                last_date = date
                last_tag = result['name']
        if obj['next']:
            url = obj['next']
        else:
            break
    print("last tag: {}, date: {}".format(last_tag, last_date))
    if not last_tag:
        raise Exception('No tag found for image: {}'.format(image_name))
    return last_tag


def create_powershell_image(folder, base_image, args):
    docker_file = open(folder + "/Dockerfile", "w+")
    docker_file.write(DOCKER_POWERSHELL.format(image=base_image, modules=",".join(args.pkg)))
    docker_file.close()


def create_python_image(folder, base_image, args):
    docker_template = DOCKER_PYTHON_ALPINE if args.linux == 'alpine' else DOCKER_PYTHON_DEBIAN
    docker_file = open(folder + "/Dockerfile", "w+")
    docker_file.write(docker_template.format(image=base_image))
    docker_file.close()
    # copy gitignore from python image
    shutil.copy(sys.path[0] + "/python/.gitignore", folder)
    print("Initializing pipenv...")
    print('========================================')
    pipenv_param = "--two" if args.python == "two" else "--three"
    my_env = os.environ.copy()
    my_env['PIPENV_MAX_DEPTH'] = '1'
    subprocess.call(["pipenv", pipenv_param], cwd=folder, env=my_env)
    if args.pkg:
        print("Installing python packages: {}".format(args.pkg))
        cmd_arr = ["pipenv", "install"]
        cmd_arr.extend(args.pkg)
        subprocess.call(cmd_arr, cwd=folder, env=my_env)
    else:
        subprocess.call(["pipenv", "lock"], cwd=folder, env=my_env)
    print("NOTE: To install additional python packages: cd {}; pipenv install <package>".format(folder))


LINUX_DIST_TO_SUFFIX = {
    'alpine': '',
    'debian': '-deb',
    'ubuntu': '-ubuntu'
}


def main():
    parser = argparse.ArgumentParser(description='Create a new docker image',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-t", "--type", help="Specify type of image to create",
                        choices=['python', 'powershell'], default='python')
    parser.add_argument("-p", "--python", help="Specify python version to use",
                        choices=['two', 'three'], default='three')
    parser.add_argument("-l", "--linux", help="Specify linux distro to use",
                        choices=['alpine', 'debian', 'ubuntu'], default='alpine')
    parser.add_argument('--pkg', action='append', help='Specify a package to install. Can be specified multiple times. ' +
                        'Each package needs to be specified with --pkg. For example: --pkg google-cloud-storage --pkg oath2client')
    parser.add_argument("name", help="The image name to use without the organization prefix. For example: ldap3")

    args = parser.parse_args()

    version = "" if (args.type == 'powershell' or args.python == 'two') else '3'
    linux = LINUX_DIST_TO_SUFFIX[args.linux]

    base_image = "demisto/{}{}{}".format(args.type, version, linux)

    print(args)
    print("docker dir: ".format(sys.path[0]))
    print("Using base image: {}".format(base_image))
    folder = "{}/{}".format(sys.path[0], args.name)
    if os.path.exists(folder):
        sys.stderr.write('Error: Folder [{}] already exists. Must specify a new image name.\n'.format(folder))
        sys.exit(1)

    last_tag = get_latest_tag(base_image)
    base_image_last = "{}:{}".format(base_image, last_tag)
    print("Latest base image: " + base_image_last)
    os.mkdir(folder)
    conf_file = open(folder + "/build.conf", "w+")
    conf_file.write("version=1.0.0\n")
    conf_file.close()
    if args.type == "python":
        create_python_image(folder, base_image_last, args)
    else:
        create_powershell_image(folder, base_image_last, args)
    print('Adding: {} to .dependabot/config.yml ...'.format(folder))
    subprocess.check_call([sys.path[0] + "/add_dependabot.sh", "docker/" + args.name])
    print('========================================')
    print("Done creating image files in folder: " + folder)
    print("\nTo build locally the docker image run: {}/build_docker.sh {}".format(sys.path[0], args.name))


if __name__ == "__main__":
    main()
