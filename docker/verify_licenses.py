#!/usr/bin/env python

import argparse
import requests
import subprocess
import json
import re
import sys


def main():
    parser = argparse.ArgumentParser(description='Verify licenses used in a docker image',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("docker_image", help="The docker image with tag version to use. For example: demisto/python3:1.5.0.27")
    args = parser.parse_args()
    with open('{}/approved_licenses.json'.format(sys.path[0])) as f:
        licenses = json.load(f)["licenses"]
    pip_list_json = subprocess.check_output(["docker", "run", "--rm", args.docker_image, "pip", "list", "--format", "json"])
    pip_list = json.loads(pip_list_json)
    for pkg in pip_list:
        name = pkg["name"]
        print("Checking license for package: {} ...".format(name))
        res = requests.get("https://pypi.org/pypi/{}/json".format(name))
        res.raise_for_status()
        pypi_info = res.json()
        for classifier in pypi_info["info"]["classifiers"]:
            # check that we have license and not just the OSI Approved string
            if classifier.startswith("License ::") and not classifier == "License :: OSI Approved":
                print("{}: found license classifier: {}".format(name, classifier))
                # check that we have at least one approved license that matches
                found = False
                for lic in licenses:
                    if re.search(lic["regex"], classifier):
                        print("{}: classifier: {} matches license: {}".format(name, classifier, lic["name"]))
                        found = True
                        break
                if not found:
                    msg = "{}: no approved license found for classifier: {}".format(name, classifier)
                    print("FAILURE: {}".format(msg))
                    raise Exception(msg)
    print("SUCCESS: completed checking all licenses for docker image: {}".format(args.docker_image))


if __name__ == "__main__":
    main()
