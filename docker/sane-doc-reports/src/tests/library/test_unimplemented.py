from sane_doc_reports.populate.Report import Report
from tests.utils import _transform


def test_unimplemented_element_generated():
    report = Report(*_transform('elements/unimplemented.json'))
    report.populate_report()

    d = report.document

    assert len(d.element.xpath('//w:p')) == 3

    # Styles or error
    assert len(d.element.xpath('//w:i[@w:val="0"]')) == 1
    assert len(d.element.xpath('//w:strike[@w:val="0"]')) == 1
    assert len(d.element.xpath('//w:color[@w:val="FF0013"]')) == 1
    assert len(d.element.xpath('//w:sz[@w:val="20"]')) == 1
    assert len(d.element.xpath('//w:u[@w:val="none"]')) == 1
