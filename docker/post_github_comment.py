#!/usr/bin/env python

import argparse
import requests
import subprocess
import os
import re
import time


def get_docker_image_size(docker_image):
    """Get the size of the image form docker hub

    Arguments:
        docker_image {string} -- the full name of hthe image
    """
    size = "failed querying size"
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
    return size


def main():
    desc = """Post a message to github about the created image. Relies on environment variables:
GITHUB_KEY: api key of user to use for posting
CIRCLE_PULL_REQUEST: pull request url to use to get the pull id. Such as: https://github.com/demisto/dockerfiles/pull/9
if CIRCLE_PULL_REQUEST will try to get issue id from last commit comment
    """
    parser = argparse.ArgumentParser(description=desc,
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("docker_image", help="The docker image with tag version to use. For example: devdemisto/python3:1.5.0.27")
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
- Image Size: `{get_docker_image_size(args.docker_image)}`
- Image ID: `{{{{ .Id }}}}`
- Created: `{{{{ .Created }}}}`
- Arch: `{{{{ .Os }}}}`/`{{{{ .Architecture }}}}`
{{{{ if .Config.Entrypoint }}}}- Entrypoint: `{{{{ json .Config.Entrypoint }}}}`
{{{{ end }}}}{{{{ if .Config.Cmd }}}}- Command: `{{{{ json .Config.Cmd }}}}`
{{{{ end }}}}- Environment:{{{{ range .Config.Env }}}}{{{{ "\\n" }}}}  - `{{{{ . }}}}`{{{{ end }}}}
- Labels:{{{{ range $key, $value := .ContainerConfig.Labels }}}}{{{{ "\\n" }}}}  - `{{{{ $key }}}}:{{{{ $value }}}}`{{{{ end }}}}
'''
    docker_info = subprocess.check_output(["docker", "inspect", "-f", inspect_format, args.docker_image]).decode()
    base_name = args.docker_image.split(':')[0]
    mode = "Dev"
    if base_name.startswith('demisto/'):
        mode = "Production"
    message = (
        "# Docker Image Ready - {}\n\n".format(mode) +
        "Docker automatic build at CircleCI has deployed your docker image: {}\n".format(args.docker_image) +
        "It is available now on docker hub at: https://hub.docker.com/r/{}/tags\n".format(base_name) +
        "Get started by pulling the image:\n" +
        "```\n" +
        "docker pull {}\n".format(args.docker_image) +
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
