from docx.table import Table

from sane_doc_reports.conf import SHOULD_HAVE_12_GRID
from sane_doc_reports.populate.Report import Report
from tests import utils
from tests.utils import _transform


def test_number_and_trend_in_report():
    report = Report(*_transform('elements/number_and_trend.json'))
    report.populate_report()
    d = report.document
    table = next(utils.iter_block_items(d))
    assert isinstance(table, Table)

    if SHOULD_HAVE_12_GRID:
        assert len(table.columns) == 12
        assert len(table.rows) == 4
    else:
        assert len(table.columns) == 9
        assert len(table.rows) == 4

    # Check that there is indeed an image
    assert len(d.element.xpath('//w:tbl//w:tbl')) == 2

    # Check that it has the right amount of rows
    assert len(d.element.xpath('//w:tbl//w:tbl//w:t')) == 5
