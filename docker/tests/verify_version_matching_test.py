#!/usr/bin/env python3

import pytest
from docker import verify_version_matching


test_data_parse_local_version = [("3",[3]),("3.11",[3,11]),("3.12.1",[3,12,1])]
@pytest.mark.parametrize("version,expected_version", test_data_parse_local_version)
def test_parse_local_version(version, expected_version):
    """
    Given
        - string version in 4.5.6 format
    When
        - running parse_local_version
    Then
        - Verify parse_local_version output

    """
    results=verify_version_matching.parse_local_version(version)
    assert results==expected_version


test_data_compare_versions = [([3],[3], True, True),
                              ([1],[3], True, False),
                              ([1],[3], True, False),
                              ([3,2],[3,2,2], True, True),([3,2],[3,2,2], False, True),
                              ([3,10,1],[3,10], False, True),([3,10,1],[3,10], True, True),
                              ([3,10,1],[3,10,0], True, False),([3,10,0],[3,10,0], True, True),
                              ((3,10,1),(3,10,0), False, False),((3,10,0),(3,10,0), False, True)]
@pytest.mark.parametrize("versions_docker,versions_file,is_caret,expected_result",
                         test_data_compare_versions)
def test_compare_versions(versions_docker,versions_file,is_caret,expected_result):
    """
    Given
        - versions_docker,versions_file
    When
        - running compare_versions
    Then
        - Verify compare_versions output

    """
    results=verify_version_matching.compare_versions(versions_docker,versions_file,is_caret)
    assert results==expected_result
