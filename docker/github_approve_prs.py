#!/usr/bin/env python3

import argparse
import requests
import os


def main():
    parser = argparse.ArgumentParser(description='Approve Github PRs. Used to mass approve dependabot prs.'
                                     ' SET GITHUB_USER and GITHUB_TOKEN env vars for authentication',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-t", "--title", help="Title prefix for prs to approve.",
                        required=False, default="Bump demisto/")
    parser.add_argument("-a", "--author", help="Author of prs to approve.",
                        required=False, default="dependabot-preview[bot]")
    parser.add_argument("-c", "--comment", help="Comment to add to the PR",
                        required=False, default="@dependabot squash and merge")
    args = parser.parse_args()
    auth = (os.environ["GITHUB_USER"], os.environ["GITHUB_TOKEN"])
    res = requests.get(
        "https://api.github.com/search/issues?q=is:pr+repo:demisto/dockerfiles+state:open+review:required&per_page", auth=auth)
    res.raise_for_status()
    open_prs = res.json().get('items')
    print("Found [{}] prs".format(len(open_prs)))
    for pr in open_prs:
        title = pr.get('title')
        user = pr.get('user')
        author = "" if not user else user.get('login')
        pr_num = pr['number']
        if title and title.startswith(args.title) and author == args.author:            
            # print("Checking review status for pr [{}]: [{}]".format(pr_num, title))            
            print("Approving PR [{}]: [{}]".format(pr_num, title))
            requests.post("https://api.github.com/repos/demisto/dockerfiles/pulls/{}/reviews".format(pr_num),
                          json={
                "event": "APPROVE"
            }, auth=auth).raise_for_status()
            requests.post("https://api.github.com/repos/demisto/dockerfiles/issues/{}/comments".format(pr_num),
                          json={
                "body": args.comment
            }, auth=auth).raise_for_status()            
        else:
            print("Skiping [{}] pr as title [{}] and author [{}] don't match".format(pr_num, title, author))


if __name__ == "__main__":
    main()
