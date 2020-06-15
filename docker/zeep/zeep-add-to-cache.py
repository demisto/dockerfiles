#!/usr/bin/env python

import argparse
import requests
import zeep
import os
from zeep.cache import SqliteCache


# will use ZEEP_STATIC_CACHE_DB env variable for the path of the cache db
def main():
    parser = argparse.ArgumentParser(description="Add a file to zeep SqliteCache. Will use default cache location.")
    parser.add_argument("url", help="The url to fetch and add to the cache. For example: https://www.w3.org/2005/05/xmlmime")
    args = parser.parse_args()
    res = requests.get(args.url)
    res.raise_for_status()
    content_type = res.headers.get('content-type')
    if content_type != 'application/xml':
        raise Exception('Expecting content type to equal: application/xml. Got: ' + content_type)
    cache = SqliteCache(path=os.environ['ZEEP_STATIC_CACHE_DB'], timeout=None)
    print("adding url: {} contents to cache db path: {}".format(args.url, cache._db_path))
    cache.add(args.url, res.content)


if __name__ == "__main__":
    main()
