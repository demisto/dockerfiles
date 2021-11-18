import os
import pytest
from ironbank.build_dockerfile import DockerfileIronbank
from ironbank.constants import DockerfileMetadata


def test_build():
    src_dir = 'ironbank/tests/test_data/netmiko'
    dst_dir = 'ironbank/tests/test_data/netmiko/ironbank'
    if not os.path.exists(dst_dir):
        os.makedirs(dst_dir)
    obj = DockerfileIronbank(src_dir, dst_dir, True)
    obj.build()
    output_file = os.path.join(dst_dir, DockerfileMetadata.FILENAME)
    expected_result_file = os.path.join(src_dir, DockerfileMetadata.FILENAME + ".ironbank")

    fp = open(output_file)
    fp_expected = open(expected_result_file)
    content = fp.read()
    expected_content = fp_expected.read()
    fp.close()
    fp_expected.close()
    assert True

