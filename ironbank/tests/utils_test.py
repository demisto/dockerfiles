import pytest
import regex
from ironbank.utils import get_last_image_tag_ironbank, get_base_image_from_dockerfile


def test_get_last_image_tag_ironbank():
    ret_val = get_last_image_tag_ironbank("ironbank/opensource/palo-alto-networks/demisto/python3")
    print(ret_val)
    assert regex.match(r"[\d.*].[\d.*].[\d.*].[\d.*]", ret_val)


def test_get_base_image_from_dockerfile():
    base_image, base_image_tag = get_base_image_from_dockerfile('ironbank/tests/test_data/netmiko/Dockerfile')
    assert base_image == 'demisto/python3-deb'
    assert base_image_tag == '3.9.5.21272'
