#!/usr/bin/env python3
import argparse
from typing import Iterable



def main():
    parser = argparse.ArgumentParser(description='Deploy a pack from a contribution PR to a branch')
    parser.add_argument('-c', '--changed_files', help='list of the changed files')
    args = parser.parse_args()

    changed_files = args.changed_files.split(";")
    validate_native_docker_image(changed_files)


def validate_native_docker_image(changed_files):
    if is_docker_being_updated(changed_files):
        # if is_update_related_to_native_dcoker()
        #     return False
        return False
    return True


def is_docker_being_updated(changed_files):
    for file in changed_files:
        print(file) 


if __name__ == '__main__':
    main()