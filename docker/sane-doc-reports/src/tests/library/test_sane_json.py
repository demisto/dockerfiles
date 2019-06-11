import pytest
import json

from fastjsonschema import JsonSchemaException

from sane_doc_reports.domain.SaneJson import SaneJson
from tests.utils import get_mock
from sane_doc_reports.domain.SaneJsonPage import SaneJsonPage


def test_sane_json_constructor():
    sane_json = SaneJson(get_mock('basic.json'))

    assert sane_json
    assert len(sane_json.json_data) == 2
    assert sane_json.json_data[0]['type'] == 'text'
    assert sane_json.json_data[1]['type'] == 'text'


def test_sane_json_invalid_json():
    with pytest.raises(json.JSONDecodeError):
        SaneJson(get_mock('invalid/invalid_json.json'))

    with pytest.raises(json.JSONDecodeError):
        SaneJson(get_mock('invalid/empty.json'))


def test_sane_json_invalid_not_list():
    with pytest.raises(JsonSchemaException) as e:
        SaneJson(get_mock('invalid/bad_sane_json_1.json'))
    assert 'data must be array' in str(e.value)


def test_sane_json_invalid_no_layout():
    with pytest.raises(JsonSchemaException) as e:
        SaneJson(get_mock('invalid/bad_sane_json_2.json'))

    assert "data[0] must contain ['type', 'data', 'layout'] properties" in str(
        e.value)


def test_sane_json_invalid_no_col_key():
    with pytest.raises(JsonSchemaException) as e:
        SaneJson(get_mock('invalid/bad_sane_json_3.json'))
    assert "data[0].layout must contain ['rowPos', 'columnPos', 'h', 'w']" + \
           " properties" in str(e.value)


def test_sane_json_invalid_no_row_key():
    with pytest.raises(JsonSchemaException) as e:
        SaneJson(get_mock('invalid/bad_sane_json_4.json'))
    assert "data[0].layout must contain ['rowPos', 'columnPos', 'h', 'w']" + \
           " properties" in str(e.value)


def test_sane_json_invalid_no_width_key():
    with pytest.raises(JsonSchemaException) as e:
        SaneJson(get_mock('invalid/bad_sane_json_5.json'))
    assert "data[0].layout must contain ['rowPos', 'columnPos', 'h', 'w']" + \
           " properties" in str(e.value)


def test_sane_json_invalid_no_height_key():
    with pytest.raises(JsonSchemaException) as e:
        SaneJson(get_mock('invalid/bad_sane_json_6.json'))
    assert "data[0].layout must contain ['rowPos', 'columnPos', 'h', 'w']" + \
           " properties" in str(e.value)


def test_sane_json_invalid_2ndpage_no_height_key():
    with pytest.raises(JsonSchemaException) as e:
        SaneJson(get_mock('invalid/bad_sane_json_7.json'))
    assert "data[1].layout must contain ['rowPos', 'columnPos', 'h', 'w']" + \
           " properties" in str(e.value)


def test_sane_json_invalid_layout_keys():
    with pytest.raises(JsonSchemaException) as e:
        SaneJson(get_mock('invalid/invalid_layout_keys.json'))
    assert 'data[0].layout.h must be bigger than or equal to 1' in str(e.value)


def test__separate_pages():
    # Sorry for checking a private function
    sane_json = SaneJson(get_mock('three_pages.json'))
    assert len(sane_json._separate_pages()) == 3


def test_pages_grid_constructor():
    sane_json = SaneJson(get_mock('basic.json'))
    assert len(sane_json.sane_pages) == 1

    first_page = sane_json.sane_pages[0]
    assert isinstance(first_page, SaneJsonPage)
    assert len(first_page) == 2
