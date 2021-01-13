from sane_doc_reports import utils
from sane_doc_reports.conf import PYDOCX_FONT_COLOR, PYDOCX_FONT_BOLD, \
    DEFAULT_TABLE_STYLE, DEBUG, PYDOCX_FONT_SIZE
from sane_doc_reports.domain import CellObject, Section
from sane_doc_reports.domain.Wrapper import Wrapper
from sane_doc_reports.elements import table
from sane_doc_reports.populate.utils import insert_text
from sane_doc_reports.domain.Section import Section as SectionObject

class ItemsSectionWrapper(Wrapper):
    """ Mainly used to fix the old json's globalSection """
    style = {
        'key': {
            PYDOCX_FONT_COLOR: '#404142',
            PYDOCX_FONT_BOLD: True,
        },
        'value': {
            PYDOCX_FONT_BOLD: False,
        },
        'title': {
            PYDOCX_FONT_SIZE: 14,
            PYDOCX_FONT_COLOR: '#768BA1',
            PYDOCX_FONT_BOLD: True,
        }
    }

    display_types = {
        'CARD': 'card',
        'ROW': 'row'
    }

    def wrap(self, invoked_from_wrapper=False):
        # Handle called from another wrapper.
        items = self.section.contents

        if items == "":
            return

        if not isinstance(items, list):
            raise ValueError('ItemsSection does not have valid contents ' +
                             '(must be a list)')

        table_width = max(items, key=lambda x: x['endCol']).get('endCol')
        row_count = max(items, key=lambda x: x.get('index', 0)).get('index') + 1

        title_offset = 0
        has_title = 'title' in self.section.extra
        if has_title:
            title_offset += 1


        item_table = self.cell_object.cell.add_table(rows=row_count+title_offset,
                                                     cols=table_width)
        if DEBUG:
            item_table.style = DEFAULT_TABLE_STYLE

        if has_title:
            section_title = self.section.extra['title']
            insert_text(item_table.cell(0,0), section_title + '\n', self.style['title'])

        for item in items:
            row, col, col_to_merge = item.get('index', 0+title_offset), item.get(
                'startCol'), item.get('endCol')
            current_cell = item_table.cell(row+title_offset, col)
            current_cell.merge(item_table.cell(row+title_offset, col_to_merge - 1))

            field_name = item.get("fieldName", "")
            field_type = item.get("fieldType", "shortText")
            field_name = field_name[0].upper() + field_name[1:]
            field_name = f'{field_name}: '

            if item.get('displayType', self.display_types['ROW']) == \
                    self.display_types['CARD']:
                field_name += '\n'

            data = item.get("data", "")
            insert_text(current_cell, field_name, self.style['key'])

            if field_type == 'grid':
                table.invoke(self.cell_object,
                             SectionObject('table', data,
                                     self.section.layout, {}))
            else:
                insert_text(current_cell, data, self.style['value'])


def invoke(cell_object: CellObject, section: Section,
           invoked_from_wrapper=False):
    if section.type != 'items_section':
        err_msg = f'Called items_section but not items_section -  [{section}]'
        return utils.insert_error(cell_object, err_msg)

    ItemsSectionWrapper(cell_object, section).wrap(
        invoked_from_wrapper=invoked_from_wrapper)
