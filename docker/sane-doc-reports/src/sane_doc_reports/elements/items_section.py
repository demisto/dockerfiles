from sane_doc_reports import utils
from sane_doc_reports.conf import PYDOCX_FONT_COLOR, PYDOCX_FONT_BOLD, \
    DEFAULT_TABLE_STYLE, DEBUG
from sane_doc_reports.domain import CellObject, Section
from sane_doc_reports.domain.Wrapper import Wrapper
from sane_doc_reports.populate.utils import insert_text


class ItemsSectionWrapper(Wrapper):
    """ Mainly used to fix the old json's globalSection """
    style = {
        'key': {
            PYDOCX_FONT_COLOR: '#404142b3',
            PYDOCX_FONT_BOLD: True,
        },
        'value': {
            PYDOCX_FONT_BOLD: False,
        }
    }

    display_types = {
        'CARD': 'card',
        'ROW': 'row'
    }

    def wrap(self, invoked_from_wrapper=False):
        # Handle called from another wrapper.
        items = self.section.contents

        if not isinstance(items, list):
            raise ValueError('ItemsSection does not have valid contents ' +
                             '(must be a list)')

        table_width = max(items, key=lambda x: x['endCol']).get('endCol')
        row_count = max(items, key=lambda x: x.get('index', 0)).get('index') + 1

        item_table = self.cell_object.cell.add_table(rows=row_count,
                                                     cols=table_width)

        if DEBUG:
            item_table.style = DEFAULT_TABLE_STYLE

        for item in items:
            row, col, col_to_merge = item.get('index', 0), item.get(
                'startCol'), item.get('endCol')
            current_cell = item_table.cell(row, col)
            current_cell.merge(item_table.cell(row, col_to_merge - 1))

            field_name = item.get("fieldName", "")
            field_name = field_name[0].upper() + field_name[1:]
            field_name = f'{field_name}: '

            if item.get('displayType', self.display_types['ROW']) == \
                    self.display_types['CARD']:
                field_name += '\n'

            insert_text(current_cell, field_name, self.style['key'])
            insert_text(current_cell, item.get("data", ""), self.style['value'])


def invoke(cell_object: CellObject, section: Section,
           invoked_from_wrapper=False):
    if section.type != 'items_section':
        err_msg = f'Called items_section but not items_section -  [{section}]'
        return utils.insert_error(cell_object, err_msg)

    ItemsSectionWrapper(cell_object, section).wrap(
        invoked_from_wrapper=invoked_from_wrapper)
