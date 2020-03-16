import argparse
import json
import logging
import os
import re
import urllib.request
import urllib.parse

"""
Heavily inspired by:
https://github.com/hellohippo/circleci-artifact-getter
- Removed outside dependencies and simplified for our use.

Usage example

(Create a build artifact token here: https://circleci.com/gh/demisto/<project>/edit#api)

Use like so:
python get_build_artifacts.py --token <token> --project <project name> --branch master --filter "regex"


"""

API_URL = 'https://circleci.com/api/v1.1/project/github'
CURRENT_ORGANIZATION = "demisto"


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--filter", required=True)
    parser.add_argument("--organization", required=False,
                        default=CURRENT_ORGANIZATION)
    return vars(parser.parse_args())


def send_request(url, params):
    headers = {'Accept': 'application/json'}

    params = urllib.parse.urlencode(params)
    url += f"?{params}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    response = urllib.request.urlopen(req)
    if response.getcode() == 200:
        return response.read()
    else:
        raise IOError(
            'Received code {}: {}'.format(response.getcode(), response.read()))


def get_latest_build_number(base_url, branch, token):
    logging.info('Getting latest successful build on {}'.format(branch))
    params = {'circle-token': token, 'limit': 1, 'filter': 'successful'}
    url = '{}/tree/{}'.format(base_url, branch)
    latest_build = send_request(url, params)
    latest_build_json = json.loads(latest_build)
    return latest_build_json[0]['build_num']


def get_artifacts(base_url, build_number, artifact_filter, token):
    params = {'circle-token': token}
    url = '{}/{}/artifacts'.format(base_url, build_number)
    artifacts = send_request(url, params)
    result = []
    for artifact in json.loads(artifacts):
        # If matches then return it
        if re.match(artifact_filter, artifact['path']):
            result.append(artifact['url'])
    return result


def download_artifacts(artifacts, token):
    logging.info('Downloading files ...')
    params = {'circle-token': token}

    for url in artifacts:
        rsp = send_request(url, params)
        with open(os.path.basename(url), "w") as f:
            f.write(rsp)
            logging.info('Wrote {}'.format(f.name))


def main():
    args = get_args()
    token = args["token"]
    project = args["project"]
    branch = args["branch"]
    filter = args["filter"]
    org = args["organization"]

    base_url = '{}/{}/{}'.format(API_URL, org, project)
    latest_build = get_latest_build_number(base_url, branch, token)
    logging.info(
        'Latest successful build on {} is #{}'.format(branch,
                                                      latest_build))
    artifacts = get_artifacts(base_url, latest_build, filter, token)
    download_artifacts(artifacts, token)
    logging.info('Done downloading artifacts!')


if __name__ == "__main__":
    main()
