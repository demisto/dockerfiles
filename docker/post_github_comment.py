#!/usr/bin/env python
import argparse
from pathlib import Path

import requests
import subprocess
import os
import re
import time

ARTIFACTS_FOLDER = Path(os.getenv("ARTIFACTS_FOLDER", "."))


def get_docker_image_size(docker_image, is_contribution: bool = False) -> str:
    """
    Get the size of the image from docker hub or locally, depending on whether we're contributing or not.

    Arguments:
        docker_image {string} -- the full name of the image
        is_contribution {bool} -- flag whether we should get the image size from Dockerhub, or locally

    Returns:
    - `str` containing the Docker image in MB, e.g. '12.34 MB'.
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
                break
            except Exception as ex:
                print("Attempt [{}] failed getting image size for image: {}. Err: {}".format(i, docker_image, ex))
                if i != 3:
                    print("Sleeping 5 seconds and trying again...")
                    time.sleep(5)
    else:
        docker_image_tar = ARTIFACTS_FOLDER / convert_docker_image_tar(docker_image)
        if docker_image_tar.exists():
            size_bytes = docker_image_tar.stat().st_size
            size = '{0:.2f} MB'.format(float(size_bytes)/1024/1024)
        else:
            print(f"Docker image '{docker_image_tar}' doesn't exist in filesystem")
    return size


def convert_docker_image_tar(docker_image: str) -> str:
    """
    Helper function to convert the Docker image to a valid path.
    For example, `devdemisto/bottle2:1.0.0.89478.tar.gz` -> `devdemisto_bottle2:1.0.0.89478.tar.gz`.

    Arguments:
    - `docker_image` (``str``): The docker image filename.

    Returns:
    - `str` of the fixed Docker image TAR.
    """
    return f"{docker_image.replace('/', '__')}.tar.gz"


def get_pr_comments_url() -> str | None:
    if os.getenv('PR_NUM'):
        pr_num = os.getenv('PR_NUM')
        print("PR number found from environment: " + pr_num)
        return f'https://api.github.com/repos/demisto/dockerfiles/issues/{pr_num}/comments'

    # try to get from comment
    last_comment = subprocess.check_output(["git", "log", "-1", "--pretty=%B"], text=True)
    m = re.search(r"#(\d+)", last_comment, re.MULTILINE)
    if not m:
        print("No issue id found in the last commit comment. Ignoring: \n------\n{}\n-------".format(last_comment))
        return None
    issue_id = m.group(1)
    print("Issue id found from the last commit comment: " + issue_id)
    post_url = "https://api.github.com/repos/demisto/dockerfiles/issues/{}/comments".format(issue_id)
    return post_url


def main():
    desc = """Post a message to github about the created image. Relies on environment variables:
XSOAR_BOT_GITHUB_TOKEN: api key of user to use for posting
PR_NUM: the PR number to post to. If not set, it will try to infer it from the last commit message.
    """
    parser = argparse.ArgumentParser(description=desc,
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("docker_image", help="The docker image with tag version to use. For example: devdemisto/python3:1.5.0.27")
    parser.add_argument("--is_contribution", help="Whether the PR is a contribution or not", action="store_true", default=False)
    args = parser.parse_args()
    print("Posting to github about image: " + args.docker_image)
    post_url = get_pr_comments_url()
    if not post_url:
        return
    print('Found PR Comments URL: {post_url}')
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
    if args.is_contribution:
        saved_docker_image = convert_docker_image_tar(args.docker_image)
        message = (
            title +
            "Docker automatic build has completed. The Docker image is available from the assigned reviewer to be loaded locally.\n\n" +
            "To load it locally run the following command:\n" +
            "```bash\n" +
            f"gunzip {saved_docker_image} | docker load\n" +
            "```\n" +
            docker_info
        )
    else:
        message = (
            title +
            "Docker automatic build has deployed your docker image: {}\n".format(args.docker_image) +
            "It is available now on docker hub at: https://hub.docker.com/r/{}/tags\n".format(base_name) +
            "Get started by pulling the image:\n" +
            "```\n" +
            "docker pull {}\n".format(args.docker_image) +
            "```\n" +
            docker_info
        )
    print("Going to post comment:\n\n{}".format(message))
    res = requests.post(post_url, json={"body": message}, auth=(os.environ['XSOAR_BOT_GITHUB_TOKEN'], 'x-oauth-basic'))
    try:
        res.raise_for_status()
    except Exception as ex:
        print("Failed comment post: {}".format(ex))    


if __name__ == "__main__":
    main()
