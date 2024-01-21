import pytest
import tempfile

from utils.validate_deprecated_dockers_json import *


def test_parse_config_contents():
    """
    Given a config file
    When calling parse_config_contents
    The file is parsed correctly without comment lines
    """
    file_contents = """
 key1=val1
key2= val2
key3=val3 
# some comment
key4 = val4
"""
    expected_dict = {'key1': 'val1', 'key2': 'val2', 'key3': 'val3', 'key4': 'val4'}
    assert parse_config_contents(file_contents) == expected_dict


def test_get_entry_by_name():
    """
    Given a deprecated json file
    When calling get_entry_by_name with a name that exists
    Then the proper config is returned
    """
    previous_json = [first := {
        "created_time_utc": "2022-05-31T17:51:17.226278Z",
        "image_name": "demisto/aiohttp",
        "reason": "Use the demisto/py3-tools docker image instead."
    },
                     second := {
                         "created_time_utc": "2023-10-24T11:40:55.948482Z",
                         "image_name": "demisto/akamai",
                         "reason": "Use the demisto/auth-utils docker image instead."
                     },
                     third := {
                         "created_time_utc": "2022-05-31T17:51:30.043632Z",
                         "image_name": "demisto/algorithmia",
                         "reason": "Use the demisto/py3-tools docker image instead."
                     },
                     {
                         "created_time_utc": "2022-05-31T17:51:30.043632Z",
                         "image_name": "demisto/heretwice",
                         "reason": "Use the demisto/py3-tools docker image instead."
                     },
                     {
                         "created_time_utc": "2022-05-31T17:51:30.043632Z",
                         "image_name": "demisto/heretwice",
                         "reason": "Use the demisto/py3-tools docker image instead."
                     }
                     ]
    assert get_entry_by_name("demisto/aiohttp", previous_json) == first
    assert get_entry_by_name("demisto/akamai", previous_json) == second
    assert get_entry_by_name("demisto/algorithmia", previous_json) == third
    assert get_entry_by_name("demisto/doesntexist", previous_json) is None
    with pytest.raises(ValueError):
        get_entry_by_name('demisto/heretwice', previous_json)


def test_compare_deprecated_images():
    """
    Given two deprecated json versions
    When calling compare_deprecated_images
    Then get the proper difference between the files
    :return:
    """
    list1 = [{
        "created_time_utc": "2022-05-31T17:51:17.226278Z",
        "image_name": "demisto/aiohttp",
        "reason": "Use the demisto/py3-tools docker image instead."
    },
        {
            "created_time_utc": "2023-10-24T11:40:55.948482Z",
            "image_name": "demisto/1",
            "reason": "Use the demisto/auth-utils docker image instead."
        },
        {
            "created_time_utc": "2022-05-31T17:51:30.043632Z",
            "image_name": "demisto/2",
            "reason": "Use the demisto/py3-tools docker image instead."
        },
        {
            "created_time_utc": "2022-05-31T17:51:30.043632Z",
            "image_name": "demisto/3",
            "reason": "Use the demisto/py3-tools docker image instead."
        },
        {
            "created_time_utc": "2022-05-31T17:51:30.043632Z",
            "image_name": "demisto/4",
            "reason": "Use the demisto/py3-tools docker image instead."
        }
    ]
    list2 = [{
        "created_time_utc": "2022-05-31T17:51:17.226278Z",
        "image_name": "demisto/aiohttp",
        "reason": "Use the demisto/py3-tools docker image instead."
    },
        {
            "created_time_utc": "2023-10-24T11:40:55.948482Z",
            "image_name": "demisto/5",
            "reason": "Use the demisto/auth-utils docker image instead."
        },
        {
            "created_time_utc": "2022-05-31T17:51:30.043632Z",
            "image_name": "demisto/6",
            "reason": "Use the demisto/py3-tools docker image instead."
        },
        {
            "created_time_utc": "2022-05-31T17:51:30.043632Z",
            "image_name": "demisto/3",
            "reason": "Use the demisto/py3-tools docker image instead."
        },
        {
            "created_time_utc": "2022-05-31T17:51:30.043632Z",
            "image_name": "demisto/4",
            "reason": "Use the demisto/py3-tools docker image instead."
        }
    ]
    only_in_1, only_in_2 = compare_deprecated_images(list1, list2)
    assert only_in_1 == {'demisto/1', 'demisto/2'}
    assert only_in_2 == {'demisto/5', 'demisto/6'}
