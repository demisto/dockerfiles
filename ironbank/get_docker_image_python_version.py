#!/usr/bin/env python3

import argparse
import os

from ironbank.utils import get_pipfile_lock_data
from ironbank.constants import Pipfile


def args_handler():
    parser = argparse.ArgumentParser(description='Retrieve python version of a given docker image')
    parser.add_argument('--docker_image_dir', help='The path to the docker image dir in the dockerfiles project',
                        required=True)
    return parser.parse_args()


def get_docker_image_python_version(docker_image_dir, pipfile_lock_data=None):
    if not pipfile_lock_data:
        pipfile_lock_data = get_pipfile_lock_data(os.path.join(docker_image_dir, Pipfile.LOCK_NAME))
    return 'python3' if '3' in pipfile_lock_data[Pipfile.META][Pipfile.REQUIRES][Pipfile.PYTHON_VERSION] else 'python'


if __name__ == '__main__':
    args = args_handler()
    print(get_docker_image_python_version(args.docker_image_dir))
