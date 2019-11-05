from sane_doc_reports import utils
from sane_doc_reports.conf import PYDOCX_FONT_SIZE, PYDOCX_FONT_NAME, \
    DEFAULT_TABLE_FONT_SIZE, PYDOCX_FONT_COLOR, PYDOCX_FONT_BOLD, \
    DEFAULT_FONT_COLOR, DEFAULT_TITLE_COLOR, DEFAULT_TITLE_FONT_SIZE, DEBUG
from sane_doc_reports.domain.CellObject import CellObject
from sane_doc_reports.domain.Element import Element
from sane_doc_reports.domain.Section import Section
from sane_doc_reports.elements import table
from sane_doc_reports.populate.utils import insert_text
from sane_doc_reports.utils import get_chart_font


class ListElement(Element):
    style = {
        'text': {
            PYDOCX_FONT_SIZE: DEFAULT_TABLE_FONT_SIZE,
            PYDOCX_FONT_NAME: get_chart_font(),
            PYDOCX_FONT_COLOR: DEFAULT_FONT_COLOR,
            PYDOCX_FONT_BOLD: False,
        },
        'title': {
            PYDOCX_FONT_NAME: get_chart_font(),
            PYDOCX_FONT_COLOR: DEFAULT_TITLE_COLOR,
            PYDOCX_FONT_SIZE: DEFAULT_TITLE_FONT_SIZE,
            PYDOCX_FONT_BOLD: False,

        }
    }

    def insert(self):
        if DEBUG:
            print("Adding list...")

        list_data = self.section.contents
        if isinstance(list_data, dict) and len(list_data) != 1:
            list_data = [list_data]

        if isinstance(list_data, dict) and len(list_data) == 1:
            # Create the parent title
            wrapper_table = self.cell_object.cell.add_table(rows=2, cols=1)
            title_cell = wrapper_table.cell(0, 0)
            title_text = list(list_data.keys())[0]
            insert_text(title_cell, title_text,
                        self.style['title'])

            # Create a list in a list because this is a grouped list
            co = CellObject(wrapper_table.cell(1, 0))

            table_data = list_data[title_text]
            invoke(co,
                   Section('list', table_data, self.section.layout,
                           {}))
        else:
            table.invoke(self.cell_object,
                         Section('table', list_data,
                                 self.section.layout,
                                 {'list_style': True}))


def invoke(cell_object, section):
    if section.type != 'list':
        err_msg = f'Called list but not list -  [{section}]'
        return utils.insert_error(cell_object, err_msg)

    ListElement(cell_object, section).insert()
