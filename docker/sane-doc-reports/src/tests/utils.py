import json
from typing import List, Tuple

from docx.document import Document
from docx.oxml.table import CT_Tbl
from docx.oxml.text.paragraph import CT_P
from docx.table import _Cell, Table
from docx.text.paragraph import Paragraph
from pathlib import Path

from sane_doc_reports.domain.Page import Page
from sane_doc_reports.domain.SaneJson import SaneJson
from sane_doc_reports.transform.Transform import Transform

MOCK_DIR = 'tests/mock_data'


def get_mock(file_name, ret_dict=True):
    package_path = Path(__file__).parent.parent
    path = package_path / Path(MOCK_DIR) / Path(file_name)

    if ret_dict:
        return json.loads(open(path, 'r').read())

    return path


def _transform(mock_file) -> Tuple[List[Page], SaneJson]:
    """ Prepare the data as sections before calling report """
    transformer = Transform(get_mock(mock_file, ret_dict=False))
    sane_json = transformer.get_sane_json()
    pages = transformer.get_pages()
    return pages, sane_json


def iter_block_items(parent):
    """
    Yield each paragraph and table child within *parent*, in document order.
    Each returned value is an instance of either Table or Paragraph. *parent*
    would most commonly be a reference to a main Document object, but
    also works for a _Cell object, which itself can contain paragraphs
    and tables.
    """
    if isinstance(parent, Document):
        parent_elm = parent.element.body
    elif isinstance(parent, _Cell):
        parent_elm = parent._tc
    else:
        raise ValueError("something's not right")

    for child in parent_elm.iterchildren():
        if isinstance(child, CT_P):
            yield Paragraph(child, parent)
        elif isinstance(child, CT_Tbl):
            yield Table(child, parent)
