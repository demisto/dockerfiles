#!/usr/bin/env python

import argparse
import requests
import subprocess
import json
import re
import sys


IS_PY3 = sys.version_info[0] == 3


def main():
    print("Python version: {}".format(sys.version))
    parser = argparse.ArgumentParser(description='Verify licenses used in a docker image',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        "docker_image", help="The docker image with tag version to use. For example: demisto/python3:1.5.0.27")
    args = parser.parse_args()
    with open('{}/approved_licenses.json'.format(sys.path[0])) as f:
        licenses = json.load(f)["licenses"]
    with open("{}/packages_license_check_exclude.json".format(sys.path[0])) as f:
        ignore_packages = json.load(f)["packages"]
    pip_list_json = subprocess.check_output(
        ["docker", "run", "--rm", args.docker_image, "pip", "list", "--format", "json"])
    pip_list = json.loads(pip_list_json)
    for pkg in pip_list:
        name = pkg["name"]
        if (name in ignore_packages and
                ((not ignore_packages[name].get("docker_images")) or
                    [x for x in ignore_packages[name].get("docker_images") if x in args.docker_image])):
            print("Ignoring package: " + name)
            continue
        print("Checking license for package: {} ...".format(name))
        classifiers = []
        found_licenses = []
        try:
            res = requests.get("https://pypi.org/pypi/{}/json".format(name))
            res.raise_for_status()
            pip_info = res.json()
            classifiers = pip_info["info"].get("classifiers")
        except Exception as ex:
            print("Failed getting info from pypi (will try pip): " + str(ex))
        for classifier in classifiers:
            # check that we have license and not just the OSI Approved string
            if classifier.startswith("License ::") and not classifier == "License :: OSI Approved":
                print("{}: found license classifier: {}".format(name, classifier))
                found_licenses.append(classifier)
        if len(found_licenses) == 0:  # try getting via pip show
            docker_cmd_arr = ["docker", "run", "--rm",
                              args.docker_image, "pip", "show", name]
            if IS_PY3:
                pip_show = subprocess.check_output(docker_cmd_arr, text=True)
            else:
                pip_show = subprocess.check_output(docker_cmd_arr)
            for line in pip_show.splitlines():
                if line.startswith("License:"):
                    print("{}: found license from pip show: {}".format(name, line))
                    found_licenses.append(line)
        for found_lic in found_licenses:
            found = False
            for lic in licenses:
                if re.search(lic["regex"], found_lic):
                    print("{}: found license: {} matches license: {}".format(
                        name, found_lic, lic["name"]))
                    found = True
                    break
            if not found:
                msg = "{}: no approved license found for license: {}".format(
                    name, found_lic)
                print("FAILURE: {}".format(msg))
                raise Exception(msg)
    print("SUCCESS: completed checking all licenses for docker image: {}".format(
        args.docker_image))


if __name__ == "__main__":
    main()
