#!/usr/bin/env python3

import argparse
import os

from ironbank.utils import get_base_image_from_dockerfile, get_last_image_tag_ironbank, BaseImagesStore
from ironbank.constants import DockerfileMetadata


def args_handler():
    parser = argparse.ArgumentParser(description='Retrieve python version of a given docker image')
    parser.add_argument('--docker_image_dir', help='The path to the docker image dir in the dockerfiles project',
                        required=True)
    return parser.parse_args()


def get_ironbank_base_image_name_and_tag(docker_image_dir):
    dockerfile_base_image, _ = get_base_image_from_dockerfile(os.path.join(docker_image_dir, DockerfileMetadata.FILENAME))
    base_images_repo = BaseImagesStore()
    base_image = base_images_repo.get_inventory()[dockerfile_base_image][0]
    base_image_tag = get_last_image_tag_ironbank(base_image)
    return f'{base_image}:{base_image_tag}'


if __name__ == '__main__':
    args = args_handler()
    print(get_ironbank_base_image_name_and_tag(args.docker_image_dir))
