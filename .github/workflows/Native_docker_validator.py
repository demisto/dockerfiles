#!/usr/bin/env python3
import argparse
from typing import Iterable
# from urllib.parse import urljoin

import requests
# from demisto_sdk.commands.common.tools import print_success


def main():
    parser = argparse.ArgumentParser(description='Deploy a pack from a contribution PR to a branch')
    parser.add_argument('-p', '--pr_number', help='PR number')
    args = parser.parse_args()

    pr_number = args.pr_number
    validate_native_docker_image(pr_number)
    
    # packs_dir_names = get_files_from_github(repo, branch, pr_number)
    # if packs_dir_names:
    #     print_success(f'Successfully updated the base branch with the following contrib packs: Packs/'
    #                   f'{", Packs/".join(packs_dir_names)}')


def get_labels(pr_number: str) -> Iterable[str]:
    """
    Get the applied labels for the pr.
    Args:
        pr_number: The PR number.

    Returns:
        A list of the applied labels, if found.
    """
    response = requests.get(f'https://api.github.com/repos/demisto/dockerfiles/pulls/{pr_number}',
                            params={'page': str(page)})
    response.raise_for_status()
    pr = response.json()
    labels = pr["labels"]
    if not labels:
        return []
    return [label.get('name', "") for label in labels]


# def get_files_from_github(username: str, branch: str, pr_number: str) -> List[str]:
#     """
#     Write the changed files content repo
#     Args:
#         username: The username of the contributor (e.g. demisto / xsoar-bot)
#         branch: The contributor branch
#         pr_number: The contrib PR
#     Returns:
#         A list of packs names, if found.
#     """
#     content_path = os.getcwd()
#     files_list = set()
#     chunk_size = 1024 * 500     # 500 Kb
#     base_url = f'https://raw.githubusercontent.com/{username}/content/{branch}/'
#     for file_path in get_pr_files(pr_number):
#         abs_file_path = os.path.join(content_path, file_path)
#         abs_dir = os.path.dirname(abs_file_path)
#         if not os.path.isdir(abs_dir):
#             os.makedirs(abs_dir)
#         with open(abs_file_path, 'wb') as changed_file:
#             with requests.get(urljoin(base_url, file_path), stream=True) as file_content:
#                 file_content.raise_for_status()
#                 for data in file_content.iter_content(chunk_size=chunk_size):
#                     changed_file.write(data)

#         files_list.add(file_path.split(os.path.sep)[1])
#     return list(files_list)


def validate_native_docker_image(pr_number):
    if "" in get_labels(pr_number):
        print("here")
        return True
    else:
        print("there")


if __name__ == '__main__':
    main()