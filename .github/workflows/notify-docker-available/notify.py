#!/usr/bin/env python3

# Runs as part of the Docker Available Workflow (see: .github/workflows/notify-docker-available.yml)
# Expecets to recieve the Github pull_request event file

import json
import argparse
import requests
import os


LINE_BEFORE_MESSAGE = 'Creating artifact of docker image...'
LINE_AFTER_MESSAGE = 'Skipping docker push for cr'

VERIFY_SSL = not (os.getenv('VERIFY_SSL') and os.getenv('VERIFY_SSL').lower() in ('false', '0', 'no'))

if not VERIFY_SSL:
    requests.packages.urllib3.disable_warnings()


def post_comment(docker_build_msg, pr_num):
    commnets_url = "https://api.github.com/repos/demisto/dockerfiles/issues/{}/comments".format(pr_num)
    token = os.getenv('GITHUB_TOKEN')
    if not token:
        raise ValueError("Can't post comment. GITHUB_TOKEN env variable is not set")
    title = "# Docker Image Ready - Dev"
    user_prefix = "github-actions"
    message = (
        title + "\n\n" +
        "Docker automatic build at CircleCI has completed. The docker image is available as an artifact of the build.\n\n" +
        "Follow the output from the build on how to load the image locally for testing:\n\n" +        
        docker_build_msg +
        "\n\n"
    )
    headers = {'Authorization': 'Bearer ' + token}
    # search for existing if so we will update
    res = requests.get(commnets_url, headers=headers, verify=VERIFY_SSL)
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
        commnets_url = f'https://api.github.com/repos/demisto/dockerfiles/issues/comments/{replace_comment_id}'
        res = requests.patch(commnets_url, json={"body": message}, headers=headers, verify=VERIFY_SSL)
    else:
        res = requests.post(commnets_url, json={"body": message}, headers=headers, verify=VERIFY_SSL)
    res.raise_for_status()


def check_docker_build(event_file):
    with open(event_file, 'r') as f:
        github_event = json.load(f)
    target_url = github_event['target_url']
    print(f'target_url: {target_url}')
    # target_url is of the form: https://circleci.com/gh/demisto/dockerfiles/5542?utm_campaign=vcs-integration-link&utm_medium=referral&utm_source=github-build-li
    target_url = target_url.split('?')[0]
    build_num = target_url.split('/')[-1]
    print(f'circleci build: {build_num}')
    res = requests.get(f'https://circleci.com/api/v1.1/project/github/demisto/dockerfiles/{build_num}', verify=VERIFY_SSL)
    res.raise_for_status()
    build_json = res.json()
    # check that this is a pull request
    if not build_json.get('pull_requests') or not build_json.get('pull_requests')[0].get('url'):
        print('Not a pull request. Skipping')
        return
    branch = build_json.get('branch')
    if not branch or not branch.startswith('pull/'):
        print(f'Skipping branch as it is not an external pull: {branch}')
        return
    pr_num = branch.split('/')[1]
    # go over steps and find build
    step = None
    for s in build_json['steps']:
        if s['name'] == 'Build Docker Images':
            step = s
    if not step:        
        raise ValueError(f'Build step not found for circle ci build json: {build_json}')
    log_output = step['actions'][0]['output_url']
    print(f'log output url: {log_output}')
    res = requests.get(log_output)
    res.raise_for_status()
    log_json = res.json()
    log_message = log_json[0]['message']
    lines = log_message.splitlines(False)
    start_indx = lines.index(LINE_BEFORE_MESSAGE) + 1
    end_indx = lines.index(LINE_AFTER_MESSAGE)
    docker_msg = '\n'.join(lines[start_indx:end_indx])
    print(f'Extracted docker message:\n{docker_msg}')
    post_comment(docker_msg, pr_num)


def main():
    parser = argparse.ArgumentParser(description='Deploy Docs',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-e", "--event", help="Github event data file which triggered the workflow", required=True)
    args = parser.parse_args()
    check_docker_build(args.event)


if __name__ == "__main__":
    main()
