from docx import Document

from sane_doc_reports.domain.CellObject import CellObject
from sane_doc_reports.domain.Section import Section
from sane_doc_reports.elements import text


def test_error():
    """
        To check the xpath: rename the .elements to .zip and
         open word/document.xml
    """

    d = Document()
    t = d.add_table(1, 1)
    test_section = Section('tedxt', "some contents", {}, {})
    c = CellObject(t.cell(0, 0))

    # This will invoke an error element because of the wrong type:
    text.invoke(c, test_section)

    assert len(d.element.xpath('//w:p')) == 3

    # Styles or error
    assert len(d.element.xpath('//w:i[@w:val="0"]')) == 1
    assert len(d.element.xpath('//w:strike[@w:val="0"]')) == 1
    assert len(d.element.xpath('//w:color[@w:val="FF0013"]')) == 1
    assert len(d.element.xpath('//w:sz[@w:val="20"]')) == 1
    assert len(d.element.xpath('//w:u[@w:val="none"]')) == 1
