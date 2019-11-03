from docx.table import Table

from sane_doc_reports.populate.Report import Report
from tests import utils
from tests.utils import _transform


def test_list_in_report():
    report = Report(*_transform('elements/list.json'))
    report.populate_report()
    d = report.document
    table = next(utils.iter_block_items(d))
    assert isinstance(table, Table)

    assert len(d.element.xpath('//w:tbl//w:tbl')) == 4

    assert len(d.element.xpath('//w:tbl//w:tbl//w:t')) == 16

    # Check that we have a string conversion
    assert len(d.element.xpath('//w:t[contains(text(),\'[]\')]')) == 1
    assert len(d.element.xpath('//w:t[contains(text(),\'0\')]')) == 1

