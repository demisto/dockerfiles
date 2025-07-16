from dockerfile_test import DockerImageValidator


def test_verify_image():
    validator = DockerImageValidator('aidockerimage')
    validator.validate()
