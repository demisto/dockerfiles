#!/usr/bin/env python3
import argparse
import requests
import os
import sys
import re


def main():
    parser = argparse.ArgumentParser(description='Deploy a pack from a contribution PR to a branch')
    parser.add_argument('-c', '--changed_files', help='list of the changed files')
    args = parser.parse_args()
    changed_files = args.changed_files.split(" ")
    return validate_native_docker(changed_files)


def validate_native_docker(changed_files) -> int:
    """
    This function validate that no native docker supported dockers are being updated.
    Args:
        changed_files: the list of files that are being changed in the current pr.

    Returns: the exit code according to wether the list of native docker supported dockers is empty or not.
    """
    updated_supported_dockers = get_updated_supported_dockers(changed_files)
    if updated_supported_dockers:
        print(f"the following dockers are updated and supported by the native docker: {', '.join(updated_supported_dockers)}. Please make sure to Check what is required to meet the criteria here: https://github.com/demisto/dockerfiles/blob/master/README.md#the-native-image-docker-validator-and-native-image-approved-label and ask your reviewer to add the 'native image approved' label.")
        return 1
    return 0


def get_updated_supported_dockers(changed_files) -> set:
    """
    This function lists the dockers that are supported by the native docker and being updated at the current pr.
    Args:
        changed_files: the list of files that are being changed in the current pr.

    Returns: the set of the native supported dockers supported dockers that are being updated.
    """
    updated_dockers = get_updated_dockers(changed_files)
    if updated_dockers:
        supported_dockers = get_supported_dockers()
        return supported_dockers & updated_dockers
    return set()


def get_updated_dockers(changed_files) -> set:
    """
    This function lists the dockers that are being updated at the current pr.
    Args:
        changed_files: the list of files that are being changed in the current pr.

    Returns: the set of the dockers that are being updated at the current pr.
    """
    dockers = []
    pattern = re.compile("docker\/.*\/.*")
    for file_path in changed_files:
        if pattern.match(file_path):
            dockers.append(os.path.basename(os.path.dirname(file_path)))
    return set(dockers)


def get_supported_dockers() -> set:
    """
    This function lists the dockers that are supported by the native docker.

    Returns: the set of the dockers that are supported by the native docker.
    """
    response = requests.get("https://raw.githubusercontent.com/demisto/content/master/Tests/docker_native_image_config.json")
    response.raise_for_status()
    data = response.json()
    native_docker_images_dict = data.get("native_images")
    supported_dockers_ls = []
    for native_docker in  native_docker_images_dict.values():
        supported_dockers_ls.extend(native_docker.get("supported_docker_images", []))
    return set(supported_dockers_ls)


if __name__ == '__main__':
    sys.exit(main())
