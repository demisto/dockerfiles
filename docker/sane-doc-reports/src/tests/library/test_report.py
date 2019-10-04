import pytest
from unittest.mock import patch
from docx.table import Table

from sane_doc_reports.populate.grid import get_vtable_merged
from sane_doc_reports.populate.Report import Report
from tests import utils
from tests.utils import _transform
from sane_doc_reports.conf import A4_MM_WIDTH, A4_MM_HEIGHT, A3_MM_WIDTH, \
    A3_MM_HEIGHT, LETTER_MM_HEIGHT, LETTER_MM_WIDTH


def test_creation_of_report_layout_basic():
    report = Report(*_transform('basic.json'))
    report.populate_report()

    d = report.document
    table = next(utils.iter_block_items(d))
    assert isinstance(table, Table)
    assert len(table.columns) == 12
    assert len(table.rows) == 2

    # Check the specific merged cells
    vtable = [
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    ]
    assert get_vtable_merged(table) == vtable


def test_creation_of_report_layout_full():
    report = Report(*_transform('grid_checks/fullgrid.json'))
    report.populate_report()

    d = report.document
    table = next(utils.iter_block_items(d))
    assert isinstance(table, Table)
    assert len(table.columns) == 12
    assert len(table.rows) == 12

    # Check the specific merged cells
    vtable = [
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ]
    assert get_vtable_merged(table) == vtable

    # Check the page breaks
    assert len(d.element.xpath('//w:pgSz[@w:orient="landscape"]')) == 0

    # Check page size
    page_sz = d.element.xpath('//w:pgSz[@w:w]')
    assert len(page_sz) == 1
    page_sz = page_sz[0]
    width, height = int(page_sz.w.mm), int(page_sz.h.mm)
    expected_width, expected_height = A4_MM_WIDTH.mm, A4_MM_HEIGHT.mm

    # Conversions aren't exact, so we are looking for a close enough difference.
    assert abs(expected_width - width) < 2
    assert abs(expected_height - height) < 2


def test_creation_of_report_layout_full_a3():
    report = Report(*_transform('grid_checks/fullgrid.json'), options={
        'paper_size': 'A3'
    })
    report.populate_report()

    d = report.document
    table = next(utils.iter_block_items(d))
    assert isinstance(table, Table)
    assert len(table.columns) == 12
    assert len(table.rows) == 12

    # Check the specific merged cells
    vtable = [
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ]
    assert get_vtable_merged(table) == vtable

    # Check the page breaks
    assert len(d.element.xpath('//w:pgSz[@w:orient="landscape"]')) == 0

    # Check page size
    page_sz = d.element.xpath('//w:pgSz[@w:w]')
    assert len(page_sz) == 1
    page_sz = page_sz[0]
    width, height = int(page_sz.w.mm), int(page_sz.h.mm)
    expected_width, expected_height = A3_MM_WIDTH.mm, A3_MM_HEIGHT.mm

    # Conversions aren't exact, so we are looking for a close enough difference.
    assert abs(expected_width - width) < 2
    assert abs(expected_height - height) < 2


def test_creation_of_report_layout_full_letter():
    report = Report(*_transform('grid_checks/fullgrid.json'), options={
        'paper_size': 'letter'
    })
    report.populate_report()

    d = report.document
    table = next(utils.iter_block_items(d))
    assert isinstance(table, Table)
    assert len(table.columns) == 12
    assert len(table.rows) == 12

    # Check the specific merged cells
    vtable = [
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ]
    assert get_vtable_merged(table) == vtable

    # Check the page breaks
    assert len(d.element.xpath('//w:pgSz[@w:orient="landscape"]')) == 0

    # Check page size
    page_sz = d.element.xpath('//w:pgSz[@w:w]')
    assert len(page_sz) == 1
    page_sz = page_sz[0]
    expected_width, expected_height = int(page_sz.w.mm), int(page_sz.h.mm)
    width, height = LETTER_MM_WIDTH.mm, LETTER_MM_HEIGHT.mm

    # Conversions aren't exact, so we are looking for a close enough difference.
    assert abs(expected_width - width) < 2
    assert abs(expected_height - height) < 2


def test_creation_of_report_layout_full_landscape():
    report = Report(*_transform('grid_checks/fullgrid.json'), options={
        'orientation': 'landscape'
    })
    report.populate_report()

    d = report.document
    table = next(utils.iter_block_items(d))
    assert isinstance(table, Table)
    assert len(table.columns) == 12
    assert len(table.rows) == 12

    # Check the specific merged cells
    vtable = [
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ]
    assert get_vtable_merged(table) == vtable

    # Check the page breaks
    assert len(d.element.xpath('//w:br')) == 0

    assert len(d.element.xpath('//w:pgSz[@w:orient="landscape"]')) == 1

    # Check page size
    page_sz = d.element.xpath('//w:pgSz[@w:w]')
    assert len(page_sz) == 1
    page_sz = page_sz[0]
    width, height = int(page_sz.w.mm), int(page_sz.h.mm)
    expected_height, expected_width = A4_MM_WIDTH.mm, A4_MM_HEIGHT.mm  # orientation

    # Conversions aren't exact, so we are looking for a close enough difference.
    assert abs(expected_width - width) < 2
    assert abs(expected_height - height) < 2


def test_creation_of_report_layout_full_paged():
    report = Report(*_transform('grid_checks/fullgridpaged.json'))
    report.populate_report()

    d = report.document
    table = next(utils.iter_block_items(d))
    assert isinstance(table, Table)
    assert len(table.columns) == 12
    assert len(table.rows) == 11

    # Check the specific merged cells
    vtable = [
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ]
    assert get_vtable_merged(table) == vtable

    # Check the page breaks
    assert len(d.element.xpath('//w:br')) == 1


def test_creation_of_report_layout_merged():
    report = Report(*_transform('grid_checks/mergegrid.json'))
    report.populate_report()

    d = report.document
    table = next(utils.iter_block_items(d))
    assert isinstance(table, Table)
    assert len(table.columns) == 12
    assert len(table.rows) == 9

    # Check the specific merged cells
    vtable = [
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1],
        [1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1],
        [0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1],
        [1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1],
        [1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1],
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1],
        [1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1],
        [1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1],
    ]
    assert get_vtable_merged(table) == vtable


def test_creation_of_report_with_exception():
    # Mock an error generating the json
    with patch('sane_doc_reports.elements.table.invoke',
               side_effect=KeyError('mocked error')):
        report = Report(*_transform('elements/table.json'))
        report.populate_report()
        assert len(report.document.element.xpath(
            '//w:t[contains(text(), "mocked error")]')) == 1


def test_creation_of_report_with_exception_with_stack():
    # Mock an error generating the json
    with patch('sane_doc_reports.elements.table.invoke',
               side_effect=KeyError('mocked error')):
        report = Report(*_transform('elements/table.json'),
                        options={'trace': True})
        report.populate_report()
        assert len(report.document.element.xpath(
            '//w:t[contains(text(), "Traceback ")]')) == 1
