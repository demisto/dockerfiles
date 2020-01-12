#!/usr/bin/env python3

# Runs as part of the Docker Available Workflow (see: .github/workflows/notify-docker-available.yml)
# Expecets to recieve the Github pull_request event file

import json
import argparse
import requests


def check_docker_build(event_file):
    with open(event_file, 'r') as f:
        github_event = json.load(f)
    print(f'github evnet: {github_event}')


def main():
    parser = argparse.ArgumentParser(description='Deploy Docs',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-e", "--event", help="Github event data file which triggered the workflow", required=True)
    args = parser.parse_args()
    check_docker_build(args.event)


if __name__ == "__main__":
    main()
