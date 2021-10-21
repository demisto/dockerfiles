#!/usr/bin/env python

import argparse
import requests
import subprocess
import os
import re


def post_comment(image_commit_map):
    if not os.environ.get('GITHUB_KEY'):
        print("No github key set. Will not post a message!")
        return
    if os.environ.get('CIRCLE_PULL_REQUEST'):
        # change: https://github.com/demisto/dockerfiles/pull/9
        # to: https://api.github.com/repos/demisto/dockerfiles/issues/9/comments
        post_url = os.environ['CIRCLE_PULL_REQUEST'].replace('github.com', 'api.github.com/repos').replace('pull', 'issues') + "/comments"
    else:
        # try to get from comment
        last_comment = subprocess.check_output(["git", "log", "-1", "--pretty=%B"])
        m = re.search(r"#(\d+)", last_comment, re.MULTILINE)
        if not m:
            print("No issue id found in last commit comment. Ignoring: \n------\n{}\n-------".format(last_comment))
            return
        issue_id = m.group(1)
        print("Issue id found from last commit comment: " + issue_id)
        post_url = "https://api.github.com/repos/demisto/dockerfiles/issues/{}/comments".format(issue_id)

    message = f"# Ironbank Generated Images"
    commit = os.environ.get('CIRCLE_SHA1')
    if commit:
        message += f" - Commit: {commit}"
    message += "\n\n"
    for item in image_commit_map:
        image_name, commit_sha = item.split('=')
        params = {'sha': commit_sha}
        url = f'https://repo1.dso.mil/api/v4/projects/dsop%2Fopensource%2Fpalo-alto-networks%2Fdemisto%2F{image_name}/pipelines'
        try:
            res = requests.get(url=url, params=params, verify=False)
        except Exception as e:
            import logging
            logging.error(f'Failed to commit the image {image_name}, error: {str(e)}')
            raise

        commit_pipeline = res.json()[0]
        pipeline_url = commit_pipeline.get('web_url', '')
        message += f"- {image_name}: [{pipeline_url}]({pipeline_url})\n"
    print("Going to post comment:\n\n{}".format(message))
    res = requests.post(post_url, json={"body": message}, auth=(os.environ['GITHUB_KEY'], 'x-oauth-basic'))
    try:
        res.raise_for_status()
    except Exception as ex:
        print("Failed comment post: {}".format(ex))


def args_handler():
    desc = """Post a message to github about the created image. Relies on environment variables:
    GITHUB_KEY: api key of user to use for posting
    CIRCLE_PULL_REQUEST: pull request url to use to get the pull id. Such as: https://github.com/demisto/dockerfiles/pull/9
    if CIRCLE_PULL_REQUEST will try to get issue id from last commit comment"""
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('--image_commit_map', help='The image commit map', required=True)
    return parser.parse_args()


def main():
    args = args_handler()
    image_commit_map = args.image_commit_map.split(' ')
    print(image_commit_map)
    post_comment(image_commit_map)


if __name__ == "__main__":
    main()
