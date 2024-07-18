#!/usr/bin/env python3

from docker import verify_version_matching
import pytest
test_get_operator_and_version = [
    (">=3.10", ["3", "10"], ">="),
    ("<=3.10", ["3", "10"], "<="),
    ("<3.11", ["3", "11"], "<"),
    (">3.11", ["3", "11"], ">"),
    ("^3.10", ["3", "10"], "^"),
    ("3.10", ["3", "10"], ""),
    ("~3.10", ["3", "10"], "~"),
    ("!=3.10", ["3", "10"], "!="),
]


@pytest.mark.parametrize(
    "version,expected_version,expected_operator", test_get_operator_and_version
)
def test_get_operator_and_version(version, expected_version, expected_operator):
    """
    Given
        - version
    When
        - running get_operator_and_version
    Then
        - Verify get_operator_and_version output

    """
    version, operator = verify_version_matching.get_operator_and_version(version)
    assert version == expected_version
    assert operator == expected_operator


test_data_parse_and_match_versions = [
    ("3.10", ">=3.10,<3.11", "pyproject.toml", (False, "~3.10")),
    ("3.11", "3.9", "pyproject.toml", (False, "3.11")),
    ("3.10.6", "3.11.5", "pyproject.toml", (False, "3.10")),
    ("3.10.6", "3.10", "pyproject.toml", (True, "")),
    ("3.10.6", "~3.10", "pyproject.toml", (True, "")),
]


@pytest.mark.parametrize(
    "docker_python_version,file_python_version,file_type, expected_result",
    test_data_parse_and_match_versions,
)
def test_parse_and_match_versions(
    docker_python_version, file_python_version, file_type, expected_result
):
    """
    Given
        - docker_python_version, file_python_version
    When
        - running parse_and_match_versions
    Then
        - Verify parse_and_match_versions output

    """
    results = verify_version_matching.parse_and_match_versions(
        docker_python_version, file_python_version, file_type
    )
    assert expected_result[0] == results[0]
    assert expected_result[1] == results[1]
