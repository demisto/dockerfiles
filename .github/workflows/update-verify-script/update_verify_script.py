#!/usr/bin/env python3
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description='Deploy a pack from a contribution PR to a branch')
    parser.add_argument('-c', '--changed_files', help='list of the changed files')
    args = parser.parse_args()
    changed_files = args.changed_files.split(" ")
    return notify_verify_script_files_require_update(changed_files)


def notify_verify_script_files_require_update(changed_files) -> int:
    """
    This function recommend the user to update the verify.py or verify.ps1 files of docker files that was updated.
    Args:
        changed_files: the list of files that are being changed in the current pr.

    Returns: the exit code according to wether the list of native docker supported dockers is empty or not.
    """
    verify_script_files_require_update = list_verify_script_files_require_update(changed_files)
    if verify_script_files_require_update:
        print(f"the following dockers were updated: {', '.join(verify_script_files_require_update)}. Please consider updating their verify script accordingly.\nFor more information please refer to the repo's README file: https://github.com/demisto/dockerfiles/blob/master/README.md#adding-a-verifypy-script")
        return 1
    return 0


def list_verify_script_files_require_update(changed_files) -> set:
    """
     This function lists all the dockers that was updated and their verify.py or verify.ps1 file wasn't updated.
    Args:
        changed_files: the list of files that are being changed in the current pr.

    Returns: the set of the verify.py or verify.ps1 files that require update.
    """
    updated_dockers = get_updated_dockers(changed_files)
    if updated_dockers:
        updated_verify_script_files = get_updated_verify_script_files(changed_files)
        return updated_dockers - updated_verify_script_files
    return set()


def get_updated_dockers(changed_files) -> set:
    """
    This function lists the dockers that are being updated at the current pr.

    A docker image is identified by the first path segment after ``docker/``
    (i.e. ``docker/<image>/...``).

    Args:
        changed_files: the list of files that are being changed in the current pr.

    Returns: the set of the dockers that are being updated at the current pr.
    """
    dockers = set()
    for file_path in changed_files:
        parts = file_path.split("/")
        if len(parts) >= 3 and parts[0] == "docker":
            dockers.add(parts[1])
    return dockers


def get_updated_verify_script_files(changed_files) -> set:
    """
    This function lists the dockers whose verify.py or verify.ps1 file is being updated at the current pr.

    The verify script lives at the docker image root (``docker/<image>/verify.py``
    or ``docker/<image>/verify.ps1``), alongside the Dockerfile.

    Args:
        changed_files: the list of files that are being changed in the current pr.

    Returns: the set of dockers whose verify.py or verify.ps1 file is being updated at the current pr.
    """
    verify_script_files = set()
    for file_path in changed_files:
        parts = file_path.split("/")
        if len(parts) == 3 and parts[0] == "docker" and parts[2] in ("verify.py", "verify.ps1"):
            verify_script_files.add(parts[1])
    return verify_script_files


if __name__ == '__main__':
    sys.exit(main())
