import argparse
import os
import sys

import pytest

# create_new_docker_image.py imports its sibling module (image_latest_tag) by bare name.
sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docker"),
)

from docker.create_new_docker_image import kebab_case_type  # noqa: E402 - needs sys.path set above


@pytest.mark.parametrize("name", ["sig-python3", "sig-a"])
def test_kebab_case_type_rejects_sig_prefix(name):
    """
    Given: an image name starting with the reserved 'sig-' prefix.
    When: validating the name.
    Then: an ArgumentTypeError is raised.
    """
    with pytest.raises(argparse.ArgumentTypeError, match="sig-"):
        kebab_case_type(name)


@pytest.mark.parametrize("name", ["python3", "my-sig-image", "signal", "sigma-tools"])
def test_kebab_case_type_accepts_non_sig_prefix(name):
    """
    Given: a valid kebab-case image name that does not start with 'sig-'.
    When: validating the name.
    Then: the name is returned unchanged.
    """
    assert kebab_case_type(name) == name
