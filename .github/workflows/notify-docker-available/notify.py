#!/usr/bin/env python3

# Runs as part of the Docker Available Workflow (see: .github/workflows/notify-docker-available.yml)
# Expecets to recieve the Github pull_request event file

import json
import argparse
import requests


LINE_BEFORE_MESSAGE = 'Creating artifact of docker image...'
LINE_AFTER_MESSAGE = 'Skipping docker push for cr'


def check_docker_build(event_file):
    with open(event_file, 'r') as f:
        github_event = json.load(f)
    target_url = github_event['target_url']
    print(f'target_url: {target_url}')
    # target_url is of the form: https://circleci.com/gh/demisto/dockerfiles/5542?utm_campaign=vcs-integration-link&utm_medium=referral&utm_source=github-build-li
    target_url = target_url.split('?')[0]
    build_num = target_url.split('/')[-1]
    print(f'circleci build: {build_num}')
    res = requests.get(f'https://circleci.com/api/v1.1/project/github/demisto/dockerfiles/{build_num}')
    res.raise_for_status()
    build_json = res.json()
    # check that this is a pull request
    pull_url = None
    if build_json.get('pull_requests') and build_json.get('pull_requests')[0].get('url'):
        pull_url = build_json.get('pull_requests')[0].get('url')
    else:
        print('Not a pull request. Skipping')
        return
    branch = build_json.get('branch')
    if not branch or not branch.startswith('pull/'):
        print(f'Skipping branch as it is not an external pull: {branch}')
        return
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


def main():
    parser = argparse.ArgumentParser(description='Deploy Docs',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-e", "--event", help="Github event data file which triggered the workflow", required=True)
    args = parser.parse_args()
    check_docker_build(args.event)


if __name__ == "__main__":
    main()
