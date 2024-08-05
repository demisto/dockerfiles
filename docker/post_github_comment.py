#!/usr/bin/env python

import argparse
from pathlib import Path
import requests
import subprocess
import os
import re
import time

CIRCLECI_DEFAULT_WORKSPACE_DIR = "/home/circleci/project"


def get_docker_image_size(docker_image, is_contribution: bool = False) -> str:
    """Get the size of the image from docker hub or CircleCI worker depending
    if we're contributing or not.

    Arguments:
        docker_image {string} -- the full name of hthe image
        is_contribution {bool} -- flag whether we should get the image size from Dockerhub or CircleCI artifacts

    Returns:
    - `str` containing the Docker image in MB, eg. '12.34 MB'.
    """
    size = "N/A"
    if not is_contribution:
        for i in (1, 2, 3):
            try:
                name, tag = docker_image.split(':')
                res = requests.get('https://hub.docker.com/v2/repositories/{}/tags/{}/'.format(name, tag))
                res.raise_for_status()
                size_bytes = res.json()['images'][0]['size']
                size = '{0:.2f} MB'.format(float(size_bytes)/1024/1024)
            except Exception as ex:
                print("[{}] failed getting image size for image: {}. Err: {}".format(i, docker_image, ex))
                if i != 3:
                    print("Sleeping 5 seconds and trying again...")
                    time.sleep(5)
    else:
        docker_image_tar = convert_docker_image_tar(docker_image)
        if docker_image_tar.exists():
            size_bytes = docker_image_tar.stat().st_size
            size = '{0:.2f} MB'.format(float(size_bytes)/1024/1024)
        else:
            print(f"Docker image '{docker_image_tar}' doesn't exist in filesystem")
    return size


def convert_docker_image_tar(docker_image: str) -> Path:
    """
    Helper function to convert the Docker image to valid path on CircleCI worker. For example:
    `devdemisto/bottle2:1.0.0.89478.tar.gz` -> `devdemisto_bottle2:1.0.0.89478.tar.gz`.

    Arguments:
    - `docker_image` (``str``): The docker image filename.

    Returns:
    - `Path` of the fixed Docker image TAR.
    """

    circleci_root_path = Path(os.environ.get("CIRCLE_WORKING_DIRECTORY", CIRCLECI_DEFAULT_WORKSPACE_DIR))
    artifacts_path = circleci_root_path / "artifacts"

    return artifacts_path / f"{docker_image.replace('/', '_')}.tar.gz"


def main():
    desc = """Post a message to github about the created image. Relies on environment variables:
GITHUB_KEY: api key of user to use for posting
CIRCLE_PULL_REQUEST: pull request url to use to get the pull id. Such as: https://github.com/demisto/dockerfiles/pull/9
if CIRCLE_PULL_REQUEST will try to get issue id from last commit comment
    """
    parser = argparse.ArgumentParser(description=desc,
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("docker_image", help="The docker image with tag version to use. For example: devdemisto/python3:1.5.0.27")
    parser.add_argument("--is_contribution", help="Whether the PR is a contribution or not", action="store_true", default=False)
    parser.add_argument(
        "-j",
        "--job-id",
        help="The CircleCI workflow job ID. Default is the environmental variable CIRCLE_WORKFLOW_JOB_ID",
        default=os.environ.get('CIRCLE_WORKFLOW_JOB_ID', ""),
        required=False,
        dest="job_id"
    )

    args = parser.parse_args()
    if not os.environ.get('GITHUB_KEY'):
        print("No github key set. Will not post a message!")
        return
    post_url = ""
    if os.environ.get('CIRCLE_PULL_REQUEST'):
        # change: https://github.com/demisto/dockerfiles/pull/9
        # to: https://api.github.com/repos/demisto/dockerfiles/issues/9/comments
        post_url = os.environ['CIRCLE_PULL_REQUEST'].replace('github.com', 'api.github.com/repos').replace('pull', 'issues') + "/comments"
    else:
        # try to get from comment
        last_comment = subprocess.check_output(["git", "log", "-1", "--pretty=%B"]).decode()
        m = re.search(r"#(\d+)", last_comment, re.MULTILINE)
        if not m:
            print("No issue id found in last commit comment. Ignoring: \n------\n{}\n-------".format(last_comment))
            return
        issue_id = m.group(1)
        print("Issue id found from last commit comment: " + issue_id)
        post_url = "https://api.github.com/repos/demisto/dockerfiles/issues/{}/comments".format(issue_id)
    inspect_format = f'''
{{{{ range $env := .Config.Env }}}}{{{{ if eq $env "DEPRECATED_IMAGE=true" }}}}## 🔴 IMPORTANT: This image is deprecated 🔴{{{{ end }}}}{{{{ end }}}}
## Docker Metadata
- Image Size: `{get_docker_image_size(args.docker_image, is_contribution=args.is_contribution)}`
- Image ID: `{{{{ .Id }}}}`
- Created: `{{{{ .Created }}}}`
- Arch: `{{{{ .Os }}}}`/`{{{{ .Architecture }}}}`
{{{{ if .Config.Entrypoint }}}}- Entrypoint: `{{{{ json .Config.Entrypoint }}}}`
{{{{ end }}}}{{{{ if .Config.Cmd }}}}- Command: `{{{{ json .Config.Cmd }}}}`
{{{{ end }}}}- Environment:{{{{ range .Config.Env }}}}{{{{ "\\n" }}}}  - `{{{{ . }}}}`{{{{ end }}}}
- Labels:{{{{ range $key, $value := .Config.Labels }}}}{{{{ "\\n" }}}}  - `{{{{ $key }}}}:{{{{ $value }}}}`{{{{ end }}}}
'''
    docker_info = subprocess.check_output(["docker", "inspect", "-f", inspect_format, args.docker_image]).decode()
    base_name = args.docker_image.split(':')[0]
    mode = "Dev"
    if base_name.startswith('demisto/'):
        mode = "Production"
    title = f"# Docker Image Ready - {mode}\n\n"
    if not args.is_contribution:
        message = (
            title +
            "Docker automatic build at CircleCI has deployed your docker image: {}\n".format(args.docker_image) +
            "It is available now on docker hub at: https://hub.docker.com/r/{}/tags\n".format(base_name) +
            "Get started by pulling the image:\n" +
            "```\n" +
            "docker pull {}\n".format(args.docker_image) +
            "```\n" +
            docker_info
        )
    elif args.job_id:
        saved_docker_image = convert_docker_image_tar(args.docker_image).name
        circleci_docker_image_url = f"https://output.circle-artifacts.com/output/job/{args.job_id}/artifacts/{os.environ.get('CIRCLE_NODE_INDEX', '0')}/docker_images/{saved_docker_image}"
        message = (
            title +
            "Docker automatic build at CircleCI has completed. The Docker image is available as an artifact of the build.\n\n" +
            "To download it and load it locally run the following command:\n" +
            "```bash\n" +
            f"curl -L '{circleci_docker_image_url}' | gunzip | docker load\n" +
            "```\n" +
            docker_info
        )
    print("Going to post comment:\n\n{}".format(message))
    res = requests.post(post_url, json={"body": message}, auth=(os.environ['GITHUB_KEY'], 'x-oauth-basic'))
    try:
        res.raise_for_status()
    except Exception as ex:
        print("Failed comment post: {}".format(ex))    


if __name__ == "__main__":
    main()
