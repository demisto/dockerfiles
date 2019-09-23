from sane_doc_reports.populate.Report import Report
from tests.utils import _transform


def test_date():
    """
        To check the xpath: rename the .elements to .zip and
         open word/document.xml
    """
    report = Report(*_transform('elements/date.json'))
    report.populate_report()

    d = report.document

    # Find 2 dates
    assert len(d.element.xpath('//w:t')) == 2

    # Find the 2 dates
    assert len(d.element.xpath('//w:t[contains(text(), "18 Dec 2012")]')) == 1
