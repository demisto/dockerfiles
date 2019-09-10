from functools import reduce

import pytest
from sane_doc_reports.domain.SaneJson import SaneJson, get_vertical_pos, row_pos
from tests.utils import get_mock
from sane_doc_reports.conf import *


def test_calculate_page_grid():
    sane_json = SaneJson(get_mock('basic.json'))
    page = sane_json.get_sane_page(0)
    assert page.calculate_page_grid() == (12, 2)


def test_no_second_page_exception():
    sane_json = SaneJson(get_mock('basic.json'))
    with pytest.raises(IndexError):
        sane_json.get_sane_page(1)


def test_calculate_page_grid_empty():
    sane_json = SaneJson(get_mock('grid_checks/onecellgrid.json'))
    page = sane_json.get_sane_page(0)
    if SHOULD_HAVE_12_GRID:
        assert page.calculate_page_grid() == (12, 1)
    else:
        assert page.calculate_page_grid() == (1, 1)


def test_calculate_page_grid_full():
    sane_json = SaneJson(get_mock('grid_checks/fullgrid.json'))
    page = sane_json.get_sane_page(0)
    assert page.calculate_page_grid() == (12, 12)


def test_calculate_page_grid_merge():
    sane_json = SaneJson(get_mock('grid_checks/mergegrid.json'))
    page = sane_json.get_sane_page(0)
    assert page.calculate_page_grid() == (12, 9)


def test_normalize_row_positions():
    sane_json = SaneJson(get_mock('grid_checks/fullgridpaged.json'))

    for sane_page in sane_json.get_sane_pages():
        sections = sane_page.get_sections()

        # Let's test that the page starts with 0
        assert sorted([row_pos(s) for s in sections])[0] == 0
