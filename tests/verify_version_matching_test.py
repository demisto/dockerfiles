#!/usr/bin/env python3

import pytest
from docker import verify_version_matching
from packaging.specifiers import SpecifierSet

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

test_get_operator_and_version = [(">=3.10","3.10",">="),
                                 ("<=3.10","3.10","<="),
                                 ("<3.11","3.11","<"),
                                 (">3.11","3.11",">"),
                                 ("^3.10","3.10","^"),
                                 ("3.10","3.10","="),
                                 ("~3.10","3.10","~"),
                                 ("!=3.10","3.10","!="),
                                 ]

@pytest.mark.parametrize("version,expected_version,expected_operator",
                         test_get_operator_and_version)
def test_get_operator_and_version(version,expected_version,expected_operator):
    """
    Given
        - version
    When
        - running get_operator_and_version
    Then
        - Verify get_operator_and_version output

    """
    version,operator=verify_version_matching.get_operator_and_version(version)
    assert version==expected_version    
    assert operator==expected_operator

test_data_parse_and_match_versions = [("3.10",">=3.10,<3.11", True),
                                      ("3.11",">=3.9,<3.11", False),
                                      ("3.10",">3.10,<=3.11", False),
                                      ("3.10.6","!=3.10.6,<=3.11", False),
                                      ("3.10.6","!=3.10.4,<=3.11", True),
                                      ("3.10","^3.10", True),
                                      ("3.10.2","^3.10", True),
                                      ("3.11","^3.10", True),
                                      ("4.11","^3.10", False),
                                      ("0.2.3","^0.2.3", True),
                                      ("0.3.3","^0.2.3", False),
                                      ("1.2.3","^1.2.3", True),
                                      ("1.2.3","^1.2", True),
                                      ("1.2.3","^1", True),
                                      ("2.2.3","^1", False),
                                      ("2.2.3","^1.2.3", False),
                                      ("2.2.3","~1.2.3", False),
                                      ("1.2.4","~1.2.3", True),
                                      ("1.2.4","~1.2", True),
                                      ("1.3.4","~1.2", False),
                                      ("1.2.4","~1", True),
                                      ("2.2.4","~1", False),
                                      ("2.2.4","2.2.4", True),
                                      ("2","2", True),
                                      ("2.2","2.2", True)]
@pytest.mark.parametrize("docker_python_version,file_python_version, expected_result",
                         test_data_parse_and_match_versions)
def test_parse_and_match_versions(docker_python_version,file_python_version, expected_result):
    """
    Given
        - docker_python_version, file_python_version
    When
        - running parse_and_match_versions
    Then
        - Verify parse_and_match_versions output

    """
    results=verify_version_matching.parse_and_match_versions(docker_python_version,file_python_version)
    assert results==expected_result



test_data_create_specifier_set = [("1.2.3","^",">=1.2.3,<2.0.0"),
                                  ("1.2","^",">=1.2,<2.0.0"),
                                  ("1","^",">=1,<2.0.0"),
                                  ("0.2.3","^",">=0.2.3,<0.3.0"),
                                  ("0.0.3","^",">=0.0.3,<0.0.4"),
                                  ("0.0","^",">=0.0,<0.1.0"),
                                  ("0","^",">=0,<1.0.0"),
                                  ("1.2.3","~",">=1.2.3,<1.3.0"),
                                  ("1.2","~",">=1.2,<1.3.0"),
                                  ("1","~",">=1,<2.0.0")]
@pytest.mark.parametrize("version_string, operator, expected_result",test_data_create_specifier_set)
def test_create_specifier_set(version_string,operator, expected_result):
    """
    Given
        - version_string, operator
    When
        - running create_specifier_set
    Then
        - Verify create_specifier_set output

    """
    results=verify_version_matching.create_specifier_set(version_string,operator)
    assert SpecifierSet(expected_result) == results
