from docx.table import Table

from sane_doc_reports.conf import SHOULD_HAVE_12_GRID, DURATION_DAYS_LABEL, \
    DURATION_HOURS_LABEL, DURATION_MINUTES_LABEL
from sane_doc_reports.populate.Report import Report
from tests import utils
from tests.utils import _transform


def test_duration():
    report = Report(*_transform('elements/duration.json'))
    report.populate_report()
    d = report.document
    table = next(utils.iter_block_items(d))
    assert isinstance(table, Table)

    if SHOULD_HAVE_12_GRID:
        assert len(table.columns) == 12
        assert len(table.rows) == 1
    else:
        assert len(table.columns) == 12
        assert len(table.rows) == 1

    # Check that there is indeed a duration table
    assert len(d.element.xpath('//w:tbl//w:tbl')) == 1

    # Check that it has the right amount of rows
    assert len(d.element.xpath('//w:tbl//w:tbl//w:t')) == 9

    # Right title
    assert len(d.element.xpath(
        "//w:t[contains(text(), 'Mean Time to Resolution (Occurred)')]")) == 1

    # Check duration value
    assert len(d.element.xpath("//w:t[contains(text(), '38')]")) == 1

    # Check that it has the right values of labels
    days = DURATION_DAYS_LABEL.strip()
    hours = DURATION_HOURS_LABEL.strip()
    mins = DURATION_MINUTES_LABEL.strip()
    print(days, hours, mins)
    assert len(d.element.xpath(f"//w:t[contains(text(), '{days}')]")) == 1
    assert len(d.element.xpath(f"//w:t[contains(text(), '{hours}')]")) == 1
    assert len(d.element.xpath(f"//w:t[contains(text(), '{mins}')]")) == 1
