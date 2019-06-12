from docx.table import Table

from sane_doc_reports.conf import SHOULD_HAVE_12_GRID
from sane_doc_reports.populate.Report import Report
from tests import utils
from tests.utils import _transform


def test_picture_in_report():
    report = Report(*_transform('elements/image.json'))
    report.populate_report()
    d = report.document
    table = next(utils.iter_block_items(d))
    assert isinstance(table, Table)

    if SHOULD_HAVE_12_GRID:
        assert len(table.columns) == 12
        assert len(table.rows) == 1
    else:
        assert len(table.columns) == 1
        assert len(table.rows) == 1

    # Check that there is indeed an image
    assert len(d.element.xpath('//pic:pic')) == 1
