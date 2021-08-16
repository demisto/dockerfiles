#!/usr/bin/env python3

import argparse
import requests


def args_handler():
    parser = argparse.ArgumentParser(description='Open a Merge Request in Repo1 image')
    parser.add_argument('--access_token', help='The access token', required=True)
    parser.add_argument('--repository', help='The repository to open the Merge Request in', required=True)
    parser.add_argument('--source_branch', help='The source branch for the Merge Request', required=True)
    parser.add_argument('--target_branch', help='The target branch for the Merge Request', required=True)
    parser.add_argument('--title', help='The title of the Merge Request', required=False)
    return parser.parse_args()


def open_merge_request(repository, source_branch, target_branch, title, access_token):
    url = f'https://repo1.dso.mil/api/v4/projects/dsop%2Fopensource%2Fpalo-alto-networks%2Fdemisto%2F{repository}/merge_requests'
    params = {
        'source_branch': source_branch,
        'target_branch': target_branch,
        'title': title
    }
    headers = {'Authorization': f'Bearer {access_token}'}
    requests.post(url=url, data=params, headers=headers)


def main():
    args = args_handler()
    repository = args.repository
    source_branch = args.source_branch
    target_branch = args.target_branch
    title = args.title or f'{repository} Update'
    access_token = args.access_token
    open_merge_request(repository, source_branch, target_branch, title, access_token)


if __name__ == '__main__':
    main()
