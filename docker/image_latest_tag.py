#!/usr/bin/env python

import argparse
import requests
import datetime
import string


def get_latest_tag(image_name, verbose=TabError):
    last_tag = None
    last_date = None
    url = "https://registry.hub.docker.com/v2/repositories/{}/tags/?page_size=25".format(image_name)
    while True:
        if verbose:
            print("Querying docker hub url: {}".format(url))
        res = requests.get(url)
        res.raise_for_status()
        obj = res.json()
        for result in obj['results']:
            name = result['name']
            if len(name) >= 20 and all(c in string.hexdigits for c in name):  # skip git sha revisions
                continue
            date = datetime.datetime.strptime(result['last_updated'], "%Y-%m-%dT%H:%M:%S.%fZ")
            if not last_date or date > last_date:
                last_date = date
                last_tag = result['name']
        if obj['next']:
            url = obj['next']
        else:
            break
    if verbose:
        print("last tag: {}, date: {}".format(last_tag, last_date))
    if not last_tag:
        raise Exception('No tag found for image: {}'.format(image_name))
    return last_tag


def main():
    parser = argparse.ArgumentParser(description='Get the lastet tag of a docker image.',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("name", help="The image name to get the tag for. For example: demisto/python3")
    parser.add_argument("--verbose", help="Specify if to print verbose data while looking up the tag",
                        choices=['true', 'false'], default='false')
    args = parser.parse_args()
    print(get_latest_tag(args.name, args.verbose == 'true'))


if __name__ == "__main__":
    main()
