from sane_doc_reports import conf
from sane_doc_reports.populate.Report import Report
from tests.utils import _transform


def test_markdown():
    """
        To check the xpath: rename the .elements to .zip and
         open word/document.xml
    """
    report = Report(*_transform('elements/markdown.json'))
    report.populate_report()

    d = report.document

    # Find 6 headings
    assert len(d.element.xpath("//w:t[contains(text(), 'Heading')]")) == 6

    # Find 3 Hrs
    assert len(d.element.xpath('//w:jc[@w:val="center"]')) == 3

    # Find Text stylings
    #   Two bold
    assert len(d.element.xpath(
        "//w:r//w:t[contains(text(), 'bold')]/preceding-sibling" +
        "::w:rPr/w:b")) == 2
    #   Two italics
    assert len(d.element.xpath(
        "//w:r//w:t[contains(text(), 'italic')]/preceding-sibling" +
        "::w:rPr/w:i")) == 2
    #   One strikethrough
    assert len(d.element.xpath(
        "//w:r//w:t[contains(text(), 'Strike')]/preceding-sibling" +
        "::w:rPr/w:strike")) == 1

    # Find one quote
    assert len(d.element.xpath(
        '//w:tbl//w:shd[@w:fill="#fff8dc"]/following::w:t[position() <2]')) == 1
    # Check the quote has a bold element inside
    assert len(d.element.xpath(
        '//w:tbl//w:shd[@w:fill="#fff8dc"]/following::w:b')) == 1

    # Find one code
    assert len(d.element.xpath(
        '//w:tbl//w:shd[@w:fill="#f5f5f5"]/following::w:t[position() <2]')) == 1
    # Check the quote has no bold element inside
    assert len(d.element.xpath(
        '//w:tbl//w:shd[@w:fill="#f5f5f5"]/following::w:b')) == 0

    # Find ULs
    assert len(
        d.element.xpath('//w:p//w:pStyle[contains(@w:val,"ListBullet")]')) == 4

    # Find OLs
    assert len(
        d.element.xpath('//w:p//w:pStyle[contains(@w:val,"ListNumber")]')) == 6

    # Find one link
    assert len(d.element.xpath("//w:hyperlink//w:t[text()='link text']")) == 1

    # Find one image
    assert len(
        d.element.xpath("//w:drawing//pic:cNvPr[@name='image.png']")) == 1

    assert len(d.element.xpath('//w:br')) == 0


def test_markdown_paged():
    report = Report(*_transform('elements/markdown_paged.json'))
    report.populate_report()

    d = report.document

    # Find 6 headings
    assert len(d.element.xpath("//w:t[contains(text(), 'Heading')]")) == 2

    # Page break (none because it is the first and only element)
    assert len(d.element.xpath('//w:br')) == 0


def test_markdown_paged():
    report = Report(*_transform('elements/markdown_paged2.json'))
    report.populate_report()

    d = report.document

    # Find 6 headings
    assert len(d.element.xpath("//w:t[contains(text(), 'Heading')]")) == 2

    # Page break
    assert len(d.element.xpath('//w:br')) == 1

    # Structure sanity check (heading -> break -> heading)
    assert len(d.element.xpath("//w:t[contains(text(),'page 1')]/following::w:br")) == 1
    assert len(d.element.xpath("//w:t[contains(text(),'page 2')]/preceding::w:br")) == 1
