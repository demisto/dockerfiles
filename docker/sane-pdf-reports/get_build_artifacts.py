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

(Create a build artifact token here: https://circleci.com/gh/<organization>/<project>/edit#api)

Use like so:
python get_build_artifacts.py --token <token> --project <project name> --branch master --filter "regex"

in sane-pdf-reports just run the docker file again.
For docker update of sane-pdf-reports,just create an empty PR.
https://github.com/demisto/server/wiki/Push-sane-pdf-report-to-production
"""

API_URL = 'https://circleci.com/api/v1.1/project/github'
CURRENT_ORGANIZATION = "demisto"
ENV_TOKEN_KEY = "CIRCLECI_ARTIFACT_TOKEN"


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--filter", required=True)
    parser.add_argument("--organization", required=False,
                        default=CURRENT_ORGANIZATION)
    return vars(parser.parse_args())


def send_request(url):
    headers = {
        'Accept': 'application/json',
        'Circle-Token': os.getenv(ENV_TOKEN_KEY, "")
    }

    req = urllib.request.Request(url, headers=headers, method="GET")
    response = urllib.request.urlopen(req)
    if response.getcode() == 200:
        return response.read()
    else:
        raise IOError(
            'Received code {}: {}'.format(response.getcode(), response.read()))


def get_artifacts(base_url, branch, artifact_filter):
    url = '{}/latest/artifacts?branch={}'.format(base_url, branch)
    logging.info(f"URL={url}")
    artifacts = send_request(url)
    result = []
    for artifact in json.loads(artifacts):
        # If matches then return it
        if re.match(artifact_filter, artifact['path']):
            result.append(artifact['url'])
    return result


def download_artifacts(artifacts):
    logging.info('Downloading artifacts files ...')

    for url in artifacts:
        rsp = send_request(url)
        with open(os.path.basename(url), "wb") as f:
            f.write(rsp)
            logging.info('Wrote {}'.format(f.name))


def main():
    # logging.basicConfig(format='%(message)s', level=logging.INFO)
    # args = get_args()
    project = 'dockerfiles'
    branch = 'mirroring_gitlab_test'
    filter = ''
    org = 'demisto'

    base_url = '{}/{}/{}'.format(API_URL, org, project)

    artifacts = get_artifacts(base_url, branch, filter)
    logging.info(f"Artifacts: {artifacts}")
    download_artifacts(artifacts)
    logging.info('Done downloading artifacts!')


if __name__ == "__main__":
    main()
