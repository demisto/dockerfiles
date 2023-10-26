import argparse


def main():
    parser = argparse.ArgumentParser(description='Deploy a pack from a contribution PR to a branch')
    parser.add_argument('dictionary', help='A dictionary that contains the content_roles')
    args = parser.parse_args()
    print(f'{args=}')
    content_roles = json.loads(args.dictionary)
    print(f'{content_roles=}')
    save_contrib_tl(content_roles)


def save_contrib_tl(content_roles):
    contrib_tl_username = content_roles.get("CONTRIBUTION_TL")
    if not contrib_tl_username:
        raise Exception("There isn't a contribution TL in .github/content_roles.json")
    # save the contrib_tl username to a file for a later use in the workflow
    with open("contrib_tl.txt", "w") as f:
        f.write(contrib_tl_username)


if __name__ == '__main__':
    main()
