#!/usr/bin/env python3
import subprocess
import requests
from docker import verify_licenses


def test_check_python_license_packages_version_in_pypi_request(mocker):
    """
    Given
        - List of pip packages
    When
        - running check_python_license and specific requesting PyPi to get the packages info.
    Then
        - Verify the request is requesting the data of the specific package version as in the docker image.
    """
    from requests import Response, Session
    mocker.patch.object(subprocess, "check_call")
    mocker.patch.object(requests, "Session")
    mocker.patch.object(subprocess, "check_output", return_value='[{"name": "package1", "version": "1.2.3"}, {"name": "package2", "version": "4.5.6"}]')

    res_a, res_b = Response(), Response()
    res_a._content = {"name": "package1", "version": "1.2.3", "info": {"classifiers": []}}
    res_b._content = {"name": "package2", "version": "4.5.6", "info": {"classifiers": []}}
    req = mocker.patch.object(Session, "get", side_effect=[res_a, res_b])

    mocker.patch.object(Response, "raise_for_status")
    mocker.patch.object(Response, "json", side_effect=[res_a.content, res_b.content])

    verify_licenses.check_python_license("", {}, {}, {})

    assert req.call_count == 2
    assert req.call_args_list[0][0][0] == "https://pypi.org/pypi/package1/1.2.3/json"
    assert req.call_args_list[1][0][0] == "https://pypi.org/pypi/package2/4.5.6/json"

