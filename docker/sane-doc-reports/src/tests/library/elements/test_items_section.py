from docx.table import Table
from datetime import date

from sane_doc_reports.populate.Report import Report
from tests import utils
from tests.utils import _transform


def test_items_section_in_report():
    report = Report(*_transform('elements/items_section.json'))
    report.populate_report()
    d = report.document
    table = next(utils.iter_block_items(d))
    assert isinstance(table, Table)


    # Check headers for 1 images (customer logo) - default
    assert len(d.sections[0].header._element.xpath('.//w:drawing')) == 1

    # Check there are enough itemsSections
    assert len(d.element.xpath('//w:tbl//w:tbl[not(*/w:tblStyle) and .//w:sz['
                               '@w:val="18"]]')) == 5

    # Check values
    assert len(d.element.xpath('//w:tbl//w:t[contains(text(), "Bot")]')) == 6
    assert len(d.element.xpath('//w:tbl//w:t[contains(text(), "2019")]')) == 7
    assert len(d.element.xpath('//w:tbl//w:t[contains(text(), "' +
                               str(date.today().year)+'")]')) == 1
    assert len(d.element.xpath('//w:tbl//w:t[contains(text(), "week")]')) == 1
    assert len(d.element.xpath('//w:tbl//w:t[contains(text(), "Timeline '
                               'Information")]')) == 1
    assert len(d.element.xpath('//w:tbl//w:t[contains(text(),'
                               ' "columnheader2")]')) == 1
