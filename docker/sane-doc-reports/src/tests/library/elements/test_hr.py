from sane_doc_reports.populate.Report import Report
from tests.utils import _transform


def test_hr():
    """
        To check the xpath: rename the .elements to .zip and
         open word/document.xml
    """
    report = Report(*_transform('elements/hr.json'))
    report.populate_report()

    d = report.document

    # Find 3 paragraphs
    assert len(d.element.xpath('//w:p')) == 6

    # Find hr
    assert len(d.element.xpath('//w:jc[@w:val="center"]')) == 3

