#!/usr/bin/env python3

import pytest
import verify_version_matching


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


test_data_compare_versions = [([3],([3],[3]), True),
                              ([1],([3],[3]), False),
                              ([3,2],([3,1],[3,1]), False),
                              ([3,2],([3,2],[3,2]), True),
                              ([3,2],([3,1],[3,2]), True),
                              ([3,2],([3,1],[3,3]), True),
                              ([3,2,3],([3,1],[3,3]), True),
                              ([3,2,3],([3,2,3],[3,2,3]), True),
                              ([1,1,1],([3,1,1],[3,1,1]), False),
                              ([3,2,2],([3,1,2],[3,1,2]), False),
                              ([3,2],([3,2,3],[3,2,3]), True),
                              ([3,2],([3,2,3],[3,2,3]), True),
                              ([3,2,2],([3,1,2],[3,1,2]), False),
                              ([3,2],([3,2,2],[3,2,2]), True),
                              ([3,10,1],([3,10],[3,10]), True),
                              ([3,10,1],([3,10],[3,10]), True),
                              ([3,10,1],([3,10,0],[3,10,0]), False),
                              ([3,10,1],([3,10,0],[3,10,1]), True),
                              ([3,10,0],([3,10,0],[3,10,0]), True),
                              ((3,10,1),([3,10,0],[3,10,0]), False),
                              ((3,10,1),([3,10,0],[3,10,0]), False),
                              ((3,10,0),([3,10,0],[3,10,0]), True)]
@pytest.mark.parametrize("versions_docker,versions_file,expected_result",
                         test_data_compare_versions)
def test_compare_versions(versions_docker,versions_file,expected_result):
    """
    Given
        - versions_docker,versions_file
    When
        - running compare_versions
    Then
        - Verify compare_versions output

    """
    results=verify_version_matching.compare_versions(versions_docker,versions_file)
    assert results==expected_result
    
test_data_parse_version_range = [(">=3.10","<3.11",('3.10', '3.11')),
                                 ("<3.11",">=3.10",('3.10', '3.11')),
                                 ("<3.11","^3.10",('3.10', '3.11')),
                                 ("^3.10","<3.11",('3.10', '3.11')),
                                 ("3.10","3.10",('3.10', '3.10'))]
@pytest.mark.parametrize("version_1,version_2,expected_result",
                         test_data_parse_version_range)
def test_parse_version_range(version_1,version_2,expected_result):
    """
    Given
        - version_1,version_2
    When
        - running parse_version_range
    Then
        - Verify parse_version_range output

    """
    results=verify_version_matching.parse_version_range(version_1,version_2)
    assert results==expected_result


test_data_parse_and_match_versions = [("3.10",">=3.10,<3.11", True)]
@pytest.mark.parametrize("docker_python_version,file_python_version, expected_result",
                         test_data_parse_and_match_versions)
def test_parse_and_match_versions(docker_python_version,file_python_version, expected_result):
    results=verify_version_matching.parse_and_match_versions(docker_python_version,file_python_version)
    assert results==expected_result
