#!/usr/bin/env python3
import argparse
import os
import sys


DOCKER_FILES_SUFFIX = ["Dockerfile", "Pipfile", "Pipfile.lock"]


def main():
    parser = argparse.ArgumentParser(description='Deploy a pack from a contribution PR to a branch')
    parser.add_argument('-c', '--changed_files', help='list of the changed files')
    args = parser.parse_args()
    changed_files = args.changed_files.split(" ")
    return list_verify_py_files_require_update(changed_files)


def notify_verify_py_files_require_update(changed_files):
    """
    This function recommend the user to update the verify.py files of docker files that was updated.
    Args:
        changed_files: the list of files that are being changed in the current pr.

    Returns: the exit code according to wether the list of native docker supported dockers is empty or not.
    """
    verify_py_files_require_update = list_verify_py_files_require_update(changed_files)
    if verify_py_files_require_update:
        print(f"the following dockers were updated: {', '.join(verify_py_files_require_update)}. Please consider updating their verify.py file accordingly.")
        return 1
    return 0


def list_verify_py_files_require_update(changed_files):
    """
     This function lists all the dockers that was updated and their verify.py wasn't updated.
    Args:
        changed_files: the list of files that are being changed in the current pr.

    Returns: the set of the verify.py files that require update.
    """
    verify_py_files_require_update = []
    updated_dockers = get_updated_dockers(changed_files)
    if updated_dockers:
        updated_verify_py_files = get_updated_verify_py_files(changed_files)
        return updated_dockers - updated_verify_py_files
    return verify_py_files_require_update


def get_updated_dockers(changed_files):
    """
    This function lists the dockers that are being updated at the current pr.
    Args:
        changed_files: the list of files that are being changed in the current pr.

    Returns: the set of the dockers that are being updated at the current pr.
    """
    dockers = []
    for file_path in changed_files:
        for suffix in DOCKER_FILES_SUFFIX:
            if file_path.endswith(suffix) and file_path.startswith("docker/"):
                dockers.append(os.path.basename(os.path.dirname(file_path)))
    return set(dockers)


def get_updated_verify_py_files(changed_files):
    """
    This function lists the verify.py files that are being updated at the current pr.
    Args:
        changed_files: the list of files that are being changed in the current pr.

    Returns: the list of the verify.py files that are being updated at the current pr.
    """
    verify_py_files = []
    for file_path in changed_files:
        if file_path.endswith("verify.py"):
            verify_py_files.append(os.path.basename(os.path.dirname(file_path)))
    return set(verify_py_files)


if __name__ == '__main__':
    sys.exit(main())
