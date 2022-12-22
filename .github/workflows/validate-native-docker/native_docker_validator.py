#!/usr/bin/env python3
import argparse


DOCKER_FILES_SUFFIX = ["Dockerfle", "Pipfile", "Pipfile.lock"]


def main():
    parser = argparse.ArgumentParser(description='Deploy a pack from a contribution PR to a branch')
    parser.add_argument('-c', '--changed_files', help='list of the changed files')
    args = parser.parse_args()
    changed_files = args.changed_files
    changed_files = args.changed_files.split(" ")
    
    validate_native_docker_image(changed_files)


def validate_native_docker_image(changed_files):
    if is_docker_being_updated(changed_files):
        if is_update_related_to_native_dcoker()
            return False
    return True


def is_docker_being_updated(changed_files):
    for file in changed_files:
        for suffix in DOCKER_FILES_SUFFIX:
            if file.endswith(suffix):
                return True
    return False


if __name__ == '__main__':
    main()