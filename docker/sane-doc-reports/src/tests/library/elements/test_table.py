from docx.table import Table

from sane_doc_reports.populate.Report import Report
from tests import utils
from tests.utils import _transform


def test_table_in_report():
    report = Report(*_transform('elements/table.json'))
    report.populate_report()
    d = report.document
    table = next(utils.iter_block_items(d))
    assert isinstance(table, Table)
    assert len(table.columns) == 12
    assert len(table.rows) == 1

    # Check that there is indeed an image
    assert len(d.element.xpath('//w:tbl//w:tbl')) == 1

    # Check that it has the right amount of rows
    assert len(d.element.xpath('//w:tbl//w:tbl//w:t')) == 22


def test_table_in_report():
    report = Report(*_transform('elements/table_widget.json'))
    report.populate_report()
    d = report.document
    table = next(utils.iter_block_items(d))
    assert isinstance(table, Table)
    assert len(table.columns) == 12
    assert len(table.rows) == 3

    # Check that there is indeed an image
    assert len(d.element.xpath('//w:tbl//w:tbl')) == 1

    # Check that it has the right amount of rows
    assert len(d.element.xpath('//w:t[contains(text(), "Eve listens")]')) == 1