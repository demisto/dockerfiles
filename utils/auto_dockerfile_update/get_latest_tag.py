import os
import time

import requests
from typing import List, Dict, Optional, Tuple, Union
import re

VERSION_REGEX = re.compile(r"([\d]+(?:\.[\d]+)+)|([\d]+)$")

DOCKERHUB_LOGIN_URL = "https://hub.docker.com/v2/users/login"
REQUEST_TIMEOUT = 30
MAX_RATE_LIMIT_RETRIES = 5

_dockerhub_jwt: Optional[str] = None
_dockerhub_jwt_fetched = False


def _get_dockerhub_jwt(refresh: bool = False) -> Optional[str]:
    """Log in to Docker Hub once per process with DOCKERHUB_USER/DOCKERHUB_PASSWORD.

    Returns None (anonymous access) when the credentials are missing or the login fails.
    """
    global _dockerhub_jwt, _dockerhub_jwt_fetched
    if _dockerhub_jwt_fetched and not refresh:
        return _dockerhub_jwt
    _dockerhub_jwt_fetched = True
    _dockerhub_jwt = None
    user, password = os.getenv("DOCKERHUB_USER"), os.getenv("DOCKERHUB_PASSWORD")
    if not (user and password):
        print("DOCKERHUB_USER/DOCKERHUB_PASSWORD not set, using anonymous Docker Hub API access")
        return None
    try:
        res = requests.post(DOCKERHUB_LOGIN_URL, json={"username": user, "password": password}, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as e:
        print(f"Docker Hub login failed: {e}, using anonymous access")
        return None
    if res.status_code != 200:
        print(f"Docker Hub login failed: HTTP {res.status_code} {res.text[:200]!r}, using anonymous access")
        return None
    _dockerhub_jwt = res.json().get("token")
    return _dockerhub_jwt


def dockerhub_get(url: str, params: Optional[Dict] = None) -> requests.Response:
    """GET a hub.docker.com API URL, authenticated when credentials exist, retrying on 429."""
    token = _get_dockerhub_jwt()
    refreshed = False
    for attempt in range(MAX_RATE_LIMIT_RETRIES):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        res = requests.get(url, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        if res.status_code == 401 and token and not refreshed:
            token, refreshed = _get_dockerhub_jwt(refresh=True), True
            continue
        if res.status_code != 429:
            break
        retry_after = res.headers.get("Retry-After", "")
        time.sleep(int(retry_after) if retry_after.isdigit() else 2 ** attempt)
    if res.status_code != 200:
        print(f"Docker Hub API {url} returned HTTP {res.status_code} "
              f"(authenticated={bool(token)}, cf-ray={res.headers.get('cf-ray')}): {res.text[:200]!r}")
    return res


def get_dockerhub_tags_list(base_url=f'https://hub.docker.com/v2/repositories', page_size=100, repo="library",
                            image_name=None, page="", full_url="", name="", ordering=""):
    """
    Get tags list from dockerhub api
    Args:
        base_url (str): base dockerhub url
        page_size (int): number between 1-100
        repo (str): the docker hub repo, will use 'library' as default
        image_name (str): docker image name
        page (int): current page to retrieve, for pagination
        name (str): filtering option used by dockerhub website
        ordering (str): sort order, e.g. 'last_updated'
        full_url (str): If provided will ignore the previous arguments and use the full url instead.

    Returns:

    """
    if not full_url:
        full_url = f"{base_url}/{repo}/{image_name}/tags"
    params = {}
    if page:
        params['page'] = page
    if name:
        params['name'] = name
    if ordering:
        params['ordering'] = ordering
    params['page_size'] = page_size
    res = dockerhub_get(full_url, params=params)

    if res.status_code == 200:
        return res.json()


def get_powershell_tags():
    """
    Gets microsoft power-shell tags list
    Returns:

    """
    res = requests.get("https://mcr.microsoft.com/v2/powershell/tags/list", timeout=60)
    if res.status_code == 200:
        return res.json()


def get_all_tags_general(repo: str, image_name: str) -> List[Dict]:
    """
    Gets all the tags for given image from dockerhub api
    Args:
        repo (str): repo name
        image_name (str): image name

    Returns: full tags list from docker hub api

    """
    tags_list = []
    next_url = ""
    while True:
        res = get_dockerhub_tags_list(repo=repo, image_name=image_name, full_url=next_url)
        if not res:
            print(f"Error receiving {repo} - {image_name} tags from this URL: - {next_url} ")
            break
        curr_tags_list = res.get('results', [])
        tags_list += curr_tags_list
        next_url = res.get('next')
        if not next_url:
            break
    return tags_list


def get_version_regex(version: str):
    """
    Convert the given version to regex string e.x. 3.10.4-alpine-10.4-1020202 -> 3.10.[\\d]+-alpine-10.[\\d]+-[\\d]+$
    Args:
        version (str): the current version string to convert

    Returns:
        converted string
    """
    versions = re.findall(VERSION_REGEX, version)
    regex_version = version
    for v in versions:
        v = v[0] if v[0] else v[-1]

        version_list = v.split('.')
        version_list[-1] = r"[\d]+"
        temp_version = r'.'.join(version_list)
        regex_version = regex_version.replace(v, temp_version)

    regex_version += '$'
    return regex_version


def parse_single_version(version: str) -> Tuple[int, int, int, int]:
    """
    convert version string to tuple
    Args:
        version (str): version string e.x. 3.14.1

    Returns:
        tuple e.x. (3,14,1) ex. 2.7.8.12312

    """
    major, minor, micro, revision = re.search(r"(\d*)\.*(\d*)\.*(\d*)\.*(\d*)", version).groups()
    return int(major or 0), int(minor or 0), int(micro or 0), int(revision or 0)


def parse_versions(full_image_name: Union[str, Dict], key='name') -> List[Tuple[int, int, int]]:
    """
    converts image name to comparable element, e.x. 3.14-alpine-10.4 -> [(3,14,0),(10,4,0)]
    Args:
        full_image_name (Union[str, Dict]): full image name
        key (str): if full_image_name is dict extract the name using this key
    Returns:
        list of tuples

    """
    if isinstance(full_image_name, dict):
        full_image_name = full_image_name[key]
    versions = re.findall(VERSION_REGEX, full_image_name)
    result_list = []
    for v in versions:
        v = v[0] if v[0] else v[-1]
        result_list.append(parse_single_version(v))
    return result_list


def get_latest_tag_from_list(current_version: str, tags_list: List, key: str = "name") -> Dict:
    """
    Get the latest relevant tag in list.
    Relevant tags - for each version in the tag the lowest version section is different
        e.x. 3.14.2-alpine-10.3 all the tags such as 3.14.X-alpine-10.X
    Args:
        current_version (str): the current version string
        tags_list (List): the full tags list
        key (str): Optional: the tags key in the element dict

    Returns:
        the latest tag element
    """
    if current_version:
        current_version_regex = re.compile(get_version_regex(current_version))
        tags_list = [element for element in tags_list if re.match(current_version_regex, element.get(key, ""))]

    latest_tag = max(tags_list, key=parse_versions)

    return latest_tag


def get_latest_tag(repo: str, image_name: str, tag: str) -> Union[Dict, str]:
    """
    Get the latest tag for given docker image
    Args:
        repo (str): docker image's repo
        image_name (str): the docker image's name
        tag (str): the docker image's tag
        for example: full docker image name 'demisto/python3:3.1.2'
            repo = demisto
            image_name = python3
            tags = 3.1.2
    Returns:
        Latest relevant tag could be a string or a dict

    """
    if repo == "mcr.microsoft.com":
        tags_list = [{'name': tag} for tag in get_powershell_tags()['tags']]
    else:
        tags_list = get_all_tags_general(repo, image_name)

    return get_latest_tag_from_list(tag, tags_list)
