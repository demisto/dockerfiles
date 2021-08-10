import pytest

from ironbank.get_docker_image_python_version import get_docker_image_python_version


@pytest.mark.parametrize('docker_image_dir, expected_output', [
        ('ironbank/tests/test_data/ippysocks', 'python'),
        ('ironbank/tests/test_data/netmiko', 'python3')
    ]
)
def test_get_docker_image_python_version(docker_image_dir, expected_output):
    assert get_docker_image_python_version(docker_image_dir) == expected_output
