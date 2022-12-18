#!/usr/bin/env python3
import argparse
from typing import Iterable

import requests


def main():
    parser = argparse.ArgumentParser(description='Deploy a pack from a contribution PR to a branch')
    parser.add_argument('-p', '--pr_number')
    args = parser.parse_args()

    pr_number = args.pr_number
    validate_native_docker_image(pr_number)
    


def get_labels(pr_number: str) -> Iterable[str]:
    """
    Get the applied labels for the pr.
    Args:
        pr_number: The PR number.

    Returns:
        A list of the applied labels, if found.
    """
    response = requests.get(f'https://api.github.com/repos/demisto/dockerfiles/pulls/{pr_number}')
    response.raise_for_status()
    pr = response.json()
    labels = pr["labels"]
    if not labels:
        return []
    return [label.get('name', "") for label in labels]


def validate_native_docker_image(pr_number):
    if "" in get_labels(pr_number):
        print("here")
        return True
    else:
        print("there")


if __name__ == '__main__':
    main()