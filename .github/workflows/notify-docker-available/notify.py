#!/usr/bin/env python3

# Runs as part of the Docker Available Workflow (see: .github/workflows/notify-docker-available.yml)
# Expecets to recieve the Github pull_request event file

import json
import argparse
from typing import Any, Optional
import requests
import os

CIRCLECI_API_V2_GET_JOB_ARTIFACTS_ENDPOINT = "https://circleci.com/api/v2/project/gh/demisto/dockerfiles/{}/artifacts"
GITHUB_API_POST_COMMENT_ENDPOINT = "https://api.github.com/repos/demisto/dockerfiles/issues/{}/comments"
GITHUB_API_REPLACE_COMMENT_ENDPOINT= "https://api.github.com/repos/demisto/dockerfiles/issues/comments/{}"

VERIFY_SSL = not (os.getenv('VERIFY_SSL') and os.getenv('VERIFY_SSL').lower() in ('false', '0', 'no'))

if not VERIFY_SSL:
    requests.packages.urllib3.disable_warnings()


def get_tar_url(artifacts: dict[str, Any]) -> Optional[str]:
    """
    Helper function to retrieve the URL to the compressed archive of the Docker image.


    Arguments:
    - `artifacts` (``dict[str, Any]``): The Circle CI artifacts V2.

    Returns:
    - `str` representing the URL to the compressed archive.
    """
    tar_url = None

    for item in artifacts.get("items", []):
        if item.get("path", "") and item.get("path", "").endswith(".tar.gz"):
            tar_url = item.get("url")
            break

    return tar_url


def post_comment(docker_image_url: str, pr_num):
    token = os.getenv('GITHUB_TOKEN')
    if not token:
        raise ValueError("Can't post comment. GITHUB_TOKEN env variable is not set")
    title = "# Docker Image Ready - Dev"
    user_prefix = "github-actions"
    message = (
        title + "\n\n" +
        "Docker automatic build at CircleCI has completed. The Docker image is available as an artifact of the build.\n\n" +
        "To download it and load it locally run the following command:\n" + 
        "```bash\n" +
        f"curl -L '{docker_image_url}' | gunzip | docker load\n" + 
        "```\n"
    )
    headers = {'Authorization': 'Bearer ' + token}
    # search for existing if so we will update
    res = requests.get(GITHUB_API_POST_COMMENT_ENDPOINT.format(pr_num), headers=headers, verify=VERIFY_SSL)
    replace_comment_id = None
    if res.status_code == 200:
        comments = res.json()
        for c in comments:
            if (c.get('user') and c.get('user').get('login') and c['user']['login'].startswith(user_prefix)
               and c.get('body') and c['body'].startswith(title)):
                replace_comment_id = c.get('id')
                print(f'replacing comment: {c}')
                break
    if replace_comment_id:
        comments_url = GITHUB_API_REPLACE_COMMENT_ENDPOINT.format(replace_comment_id)
        res = requests.patch(comments_url, json={"body": message}, headers=headers, verify=VERIFY_SSL)
    else:
        res = requests.post(GITHUB_API_POST_COMMENT_ENDPOINT.format(pr_num), json={"body": message}, headers=headers, verify=VERIFY_SSL)
    res.raise_for_status()


def check_docker_build(event_file):
    with open(event_file, 'r') as f:
        github_event = json.load(f)
    target_url = github_event['target_url']
    pr_num = github_event['number']
    print(f'target_url: {target_url}')
    # target_url is of the form: https://circleci.com/gh/demisto/dockerfiles/5542
    target_url = target_url.split('?')[0]
    build_num = target_url.split('/')[-1]
    print(f'circleci build: {build_num}')
    res = requests.get(CIRCLECI_API_V2_GET_JOB_ARTIFACTS_ENDPOINT.format(build_num), verify=VERIFY_SSL)
    res.raise_for_status()

    artifacts = res.json()
    docker_image_tar = get_tar_url(artifacts)

    if docker_image_tar:
        post_comment(docker_image_tar, pr_num)
    else:
        print(f"No Docker image archive was found in build {CIRCLECI_API_V2_GET_JOB_ARTIFACTS_ENDPOINT.format(build_num)}")


def main():
    parser = argparse.ArgumentParser(description='Deploy Docs',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-e", "--event", help="Github event data file which triggered the workflow", required=True)
    args = parser.parse_args()
    check_docker_build(args.event)


if __name__ == "__main__":
    main()
