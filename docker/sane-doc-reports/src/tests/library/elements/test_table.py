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

    assert len(d.element.xpath('//w:tbl//w:tbl')) == 1

    # Check that it has the right amount of rows
    assert len(d.element.xpath('//w:tbl//w:tbl//w:t')) == 22  # avatar is hidden


def test_table_in_report_widget():
    report = Report(*_transform('elements/table_widget.json'))
    report.populate_report()
    d = report.document
    table = next(utils.iter_block_items(d))
    assert isinstance(table, Table)
    assert len(table.columns) == 12
    assert len(table.rows) == 3

    assert len(d.element.xpath('//w:tbl//w:tbl')) == 1

    # Check that it has the right amount of rows
    assert len(d.element.xpath('//w:t[contains(text(), "Eve listens")]')) == 1


def test_table_63_cols():
    report = Report(*_transform('elements/table_63_cols.json'))
    report.populate_report()
    d = report.document
    table = next(utils.iter_block_items(d))
    assert isinstance(table, Table)

    assert len(d.element.xpath('//w:tbl//w:tbl')) == 1
    assert int(d.element.xpath('count(//w:t)')) == 64  # 63 + title


def test_table_new_json():
    report = Report(*_transform('elements/table_new_json.json'))
    report.populate_report()
    d = report.document
    table = next(utils.iter_block_items(d))
    assert isinstance(table, Table)

    assert int(d.element.xpath('count(//w:tbl)')) == 7  # grid + 5 tables


def test_table_string_in_report():
    report = Report(*_transform('elements/table_string.json'))
    report.populate_report()
    d = report.document
    table = next(utils.iter_block_items(d))
    assert isinstance(table, Table)

    assert len(d.element.xpath('//w:tbl//w:tbl')) == 1

    # Check that it has the right amount of rows
    assert len(d.element.xpath('//w:tbl//w:tbl//w:t')) == 6 # 6 cells


def test_table_empty_in_report():
    report = Report(*_transform('elements/table_empty.json'))
    report.populate_report()
    d = report.document
    table = next(utils.iter_block_items(d))
    assert isinstance(table, Table)

    assert len(d.element.xpath('//w:tbl//w:tbl')) == 1

    # Check that it has the right amount of rows
    assert len(d.element.xpath('//w:tbl//w:tbl//w:tr')) == 2
