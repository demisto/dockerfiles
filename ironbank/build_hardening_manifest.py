#!/usr/bin/env python3

import argparse
import re
import os
from ruamel.yaml import YAML

from ironbank.constants import HardeningManifestLabels, HardeningManifestResource, HardeningManifestMaintainer, \
    HardeningManifestYaml, HardeningManifestArgs, RESOURCE_REGEX, DEMISTO_REGISTRY_ROOT, DEMISTO_CONTAINERS_MAIL, \
    PANW, DEFAULT_USER, Pipfile, DOCKERFILE, DOCKERFILE_BASE_IMAGE_TAG_REGEX
from ironbank.utils import get_pipfile_lock_data
from docker.image_latest_tag import get_latest_tag


class Resource:
    """ A class that represents a resource of the hardening_manifest.yaml file """
    def __init__(self, url, filename, value):
        self.url = url
        self.filename = filename
        self.value = value

    def dump(self):
        return {
            HardeningManifestResource.FILENAME: self.filename,
            HardeningManifestResource.URL: self.url,
            HardeningManifestResource.VALIDATION: {
                HardeningManifestResource.TYPE: 'sha256',
                HardeningManifestResource.VALUE: self.value
            }
        }


class HardeningManifest:
    """ A class that represents the hardening_manifest.yaml file """
    def __init__(self, docker_image_dir, output_path, docker_packages_metadata_path):
        self.docker_image_dir = docker_image_dir
        self.docker_image_name = os.path.basename(self.docker_image_dir)
        self.output_path = os.path.join(output_path, 'hardening_manifest.yaml')
        self.docker_packages_metadata_path = docker_packages_metadata_path
        self.name = ''
        self.labels = {}
        self.args = {}
        self.tags = []
        self.resources = []
        self.maintainers = []
        self.api_version = 'v1'
        self.yaml_dict = {}
        self.pipfile_lock_data = {}
        self.python_version = ''
        self.ryaml = YAML()
        self.ryaml.preserve_quotes = True
        if os.path.exists(self.output_path):
            with open(self.output_path, 'r') as yf:
                self.old_yaml_dict = self.ryaml.load(yf)
        else:
            self.old_yaml_dict = {}

    def handle_name(self):
        self.name = os.path.join(DEMISTO_REGISTRY_ROOT, self.docker_image_name)

    def handle_labels(self):
        image_version = float(self.old_yaml_dict.get('labels', {}).get(HardeningManifestLabels.VERSION, 0)) + 0.1  # bump image version with 0.1
        self.labels = {
            HardeningManifestLabels.TITLE: HardeningManifestLabels.BASE_TITLE.format(self.docker_image_name),
            HardeningManifestLabels.DESCRIPTION: HardeningManifestLabels.BASE_DESCRIPTION.format(self.docker_image_name),
            HardeningManifestLabels.LICENSES: ' ',
            HardeningManifestLabels.URL: ' ',
            HardeningManifestLabels.VENDOR: HardeningManifestLabels.DEMISTO,
            HardeningManifestLabels.VERSION: str(image_version),
            HardeningManifestLabels.KEYWORDS: ', '.join(list(self.pipfile_lock_data[Pipfile.DEFAULT].keys())),
            HardeningManifestLabels.TYPE: HardeningManifestLabels.OPEN_SOURCE,
            HardeningManifestLabels.NAME: f'{HardeningManifestLabels.BASE_NAME}-{self.docker_image_name}'
        }

    def handle_tags(self):
        # latest tag in list's first place
        self.tags = [get_latest_tag(os.path.join('demisto', self.docker_image_name))]
        self.tags += self.old_yaml_dict.get('tags', [])

    def handle_args(self):
        self.pipfile_lock_data = get_pipfile_lock_data(os.path.join(self.docker_image_dir, Pipfile.LOCK_NAME))
        self.python_version = 'python3' if '3' in self.pipfile_lock_data[Pipfile.META][Pipfile.REQUIRES][Pipfile.PYTHON_VERSION] else 'python'

        self.args[HardeningManifestArgs.BASE_IMAGE] = os.path.join(DEMISTO_REGISTRY_ROOT, self.python_version)
        with open(os.path.join(self.docker_image_dir, DOCKERFILE), 'r') as f:
            dockerfile = f.read()
            self.args[HardeningManifestArgs.BASE_TAG] = re.findall(DOCKERFILE_BASE_IMAGE_TAG_REGEX, dockerfile)[0]

    def handle_resources(self):
        raw_resources = [r.strip(' \n') for r in open(self.docker_packages_metadata_path, 'r').readlines()]
        for raw_resource in raw_resources:
            match = re.findall(RESOURCE_REGEX, raw_resource)[0]
            url, value = match[0], match[1]
            filename = os.path.basename(url)
            self.resources.append(Resource(url, filename, value))

    def build(self):
        self.handle_name()
        self.handle_tags()
        self.handle_args()
        self.handle_labels()
        self.handle_resources()

    def dump(self):
        self.yaml_dict = {
            HardeningManifestYaml.API_VERSION: self.api_version,
            HardeningManifestYaml.NAME: self.name,
            HardeningManifestYaml.TAGS: self.tags,
            HardeningManifestYaml.ARGS: self.args,
            HardeningManifestYaml.LABELS: self.labels,
            HardeningManifestYaml.RESOURCES: [resource.dump() for resource in self.resources],
            HardeningManifestYaml.MAINTAINERS: [{
                HardeningManifestMaintainer.EMAIL: DEMISTO_CONTAINERS_MAIL,
                HardeningManifestMaintainer.NAME: PANW,
                HardeningManifestMaintainer.USERNAME: DEFAULT_USER,
                HardeningManifestMaintainer.CHT_MEMBER: False
            }]
        }

        with open(self.output_path, 'w') as yf:
            self.ryaml.dump(self.yaml_dict, yf)


def args_handler():
    parser = argparse.ArgumentParser(description='Build hardening_manifest.yaml for a given docker image, see: https://repo1.dso.mil/dsop/dccscr/-/blob/master/hardening%20manifest/README.md')
    parser.add_argument('--docker_image_dir', help='The path to the docker image dir in the dockerfiles project',
                        required=True)
    parser.add_argument('--output_path', help='Full path of folder to output the hardening_manifest.yaml file',
                        required=True)
    parser.add_argument('--docker_packages_metadata_path', help='Full path of the docker_packages_metadata.txt file',
                        required=True)
    return parser.parse_args()


def main():
    args = args_handler()
    docker_image_dir = args.docker_image_dir
    output_path = args.output_path
    docker_packages_metadata_path = args.docker_packages_metadata_path

    hardening_manifest = HardeningManifest(docker_image_dir, output_path, docker_packages_metadata_path)
    hardening_manifest.build()
    hardening_manifest.dump()


if __name__ == '__main__':
    main()
