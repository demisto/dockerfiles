from docx.table import Table

from sane_doc_reports.populate.grid import get_vtable_merged
from sane_doc_reports.populate.Report import Report
from tests import utils
from tests.utils import _transform


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
    assert len(d.element.xpath('//w:br')) == 0


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
