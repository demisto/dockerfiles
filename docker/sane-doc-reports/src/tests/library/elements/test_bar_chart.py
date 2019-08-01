from docx.table import Table

from sane_doc_reports.conf import SHOULD_HAVE_12_GRID
from sane_doc_reports.populate.Report import Report
from tests.utils import _transform, iter_block_items


def test_bar_charts_in_report():
    report = Report(*_transform('elements/bar_chart.json'))
    report.populate_report()
    d = report.document
    table = next(iter_block_items(d))
    assert isinstance(table, Table)

    if SHOULD_HAVE_12_GRID:
        assert len(table.columns) == 12
        assert len(table.rows) == 3
    else:
        assert len(table.columns) == 11
        assert len(table.rows) == 3

    # Check that there is indeed an image
    assert len(d.element.xpath('//pic:pic')) == 3
