#!/usr/bin/env python3
import argparse
import requests
import os
import sys
import click


DOCKER_FILES_SUFFIX = ["Dockerfile", "Pipfile", "Pipfile.lock"]


def main():
    parser = argparse.ArgumentParser(description='Deploy a pack from a contribution PR to a branch')
    parser.add_argument('-c', '--changed_files', help='list of the changed files')
    args = parser.parse_args()
    changed_files = args.changed_files.split(" ")
    return validate_native_docker(changed_files)


def validate_native_docker(changed_files):
    updated_supported_dockers = get_updated_supported_dockers(changed_files)
    if updated_supported_dockers:
        click.secho(f"the following dockers are updated and supported by the native docker: {','.join(updated_supported_dockers)}. Please make sure to update the native docker accordingly.", fg="red")
        return 1
    return 0


def get_updated_supported_dockers(changed_files):
    updated_supported_dockers = []
    updated_dockers_ls = get_list_of_updated_dockers(changed_files)
    if updated_dockers_ls:
        supported_dockers = get_supported_dockers()
        for updated_docker in updated_dockers_ls:
            if updated_docker in supported_dockers:
                updated_supported_dockers.append(updated_docker)
    return updated_supported_dockers


def get_list_of_updated_dockers(changed_files):
    dockers = []
    for file in changed_files:
        for suffix in DOCKER_FILES_SUFFIX:
            if file.endswith(suffix):
                dockers.append(os.path.basename(os.path.dirname(file)))
    return list(set(dockers))


def get_supported_dockers():
    response = requests.get("https://raw.githubusercontent.com/demisto/content/master/Tests/docker_native_image_config.json")
    response.raise_for_status()
    data = response.json()
    native_docker_images_dict = data.get("native_images")
    supported_dockers_ls = []
    for native_docker in  native_docker_images_dict.values():
        supported_dockers_ls.extend(native_docker.get("supported_docker_images", []))
    return list(set(supported_dockers_ls))


if __name__ == '__main__':
    sys.exit(main())
