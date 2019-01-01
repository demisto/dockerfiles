#!/usr/bin/env python

import argparse
import requests
import subprocess
import os


def main():
    desc = """Post a message to github about the created image. Relies on environment variables:
GITHUB_KEY: api key of user to use for posting
CIRCLE_PULL_REQUEST: pull request url to use to get the pull id. Such as: https://github.com/demisto/dockerfiles/pull/9
    """
    parser = argparse.ArgumentParser(description=desc,
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("docker_image", help="The docker image with tag version to use. For example: devdemisto/python3:1.5.0.27")
    args = parser.parse_args()
    if not os.environ.get('CIRCLE_PULL_REQUEST') or not os.environ.get('GITHUB_KEY'):
        print("No pull request data or github key not set. Will not post a message!")
        return
    inspect_format = '''
## Docker Metadata
- Image ID: `{{ .Id }}`
- Created: `{{ .Created }}`
- Arch: `{{ .Os }}`/`{{ .Architecture }}`
{{ if .Config.Entrypoint }}- Entrypoint: `{{ json .Config.Entrypoint }}`
{{ end }}{{ if .Config.Cmd }}- Command: `{{ json .Config.Cmd }}`
{{ end }}- Environment:{{ range .Config.Env }}{{ "\\n" }}  - `{{ . }}`{{ end }}
- Labels:{{ range $key, $value := .ContainerConfig.Labels }}{{ "\\n" }}  - `{{ $key }}:{{ $value }}`{{ end }}
'''
    docker_info = subprocess.check_output(["docker", "inspect", "-f", inspect_format, args.docker_image])
    base_name = args.docker_image.split(':')[0]
    message = (
        "# Docker Image Ready\n" +
        "Docker automatic build at CircleCI has deployed you docker image: {}\n".format(args.docker_image) +
        "It is available now on docker hub at: https://hub.docker.com/r/{}/tags\n".format(base_name) +
        "Get started by pulling the image:\n" +
        "```\n" +
        "docker pull {}\n".format(args.docker_image) +
        "```\n\n" +
        docker_info
    )
    print("Going to post comment:\n\n{}".format(message))
    # change: https://github.com/demisto/dockerfiles/pull/9
    # to: https://api.github.com/repos/demisto/dockerfiles/issues/9/comments
    post_url = os.environ['CIRCLE_PULL_REQUEST'].replace('github.com', 'api.github.com/repos').replace('pull', 'issues') + "/comments"
    requests.post(post_url, json={"body": message}, auth=(os.environ['GITHUB_KEY'], 'x-oauth-basic'))


if __name__ == "__main__":
    main()
