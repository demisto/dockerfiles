from sane_doc_reports import utils
from sane_doc_reports.domain.CellObject import CellObject
from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG, PYDOCX_FONT_SIZE, \
    DEFAULT_TABLE_FONT_SIZE, DEFAULT_TABLE_STYLE, PYDOCX_FONT_NAME, \
    PYDOCX_FONT_COLOR, DEFAULT_FONT_COLOR, DEFAULT_TITLE_FONT_SIZE, \
    PYDOCX_FONT_BOLD, DEFAULT_TITLE_COLOR, MAX_MS_TABLE_COLS_LIMIT
from sane_doc_reports.domain.Section import Section
from sane_doc_reports.elements import image
from sane_doc_reports.populate.utils import insert_text
from sane_doc_reports.utils import get_chart_font


def fix_order(ordered, readable_headers) -> list:
    """ Return the readable headers by the order given.
    In some cases the readable values are suppose to be table headers   """
    readable_headers_values = readable_headers.values()
    temp_readable = {
        **{i[0].lower() + i[1:]: i for i in readable_headers_values},
        **{i.lower(): i for i in readable_headers_values}}
    temp_readable = {k.replace(" ", ""): v for k, v in temp_readable.items()}

    # Old json format table columns are not lowercase
    inv_fix = {i: i for i in readable_headers_values}
    temp_readable = {**temp_readable, **inv_fix}

    # adding missing keys from readable headers
    diff = {k: v for k, v in readable_headers.items() if k not in temp_readable}
    temp_readable = {**temp_readable, **diff}

    # In case dict in ordered - takes the string value
    if any([isinstance(i, dict) for i in ordered]):
        ret = []
        for k in ordered:
            if isinstance(k, dict):
                key = k.get('key')
                key = readable_headers.get(key, key)
                if key not in ret and not k.get('hidden', False):
                    ret.append(key)
            else:
                ret.append(temp_readable[k])
        return ret

    ret = []
    for ordered_key in ordered:
        if isinstance(ordered_key, str):
            ret.append(temp_readable[ordered_key])
    return ret


def insert_table_image(item, item_key, insertion_cell):
    row_temp = item[item_key]
    s = Section(row_temp['type'], row_temp['data'], {}, {})
    co = CellObject(insertion_cell, add_run=False)
    image.invoke(co, s)


class TableElement(Element):
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
        },
    }

    def insert(self):
        if DEBUG:
            print("Adding table...")

        table_data = self.section.contents

        if isinstance(table_data, dict):
            table_data = table_data.get('data', table_data)

        # If table columns isn't present, use the dict values of the table data
        # as table columns (kind of like list).
        if 'tableColumns' not in self.section.layout:
            self.section.layout['tableColumns'] = list(table_data[0].keys())

        # Use and order according to readableHeaders if present.
        if 'readableHeaders' in self.section.layout:
            ordered = self.section.layout['tableColumns']
            readable_headers = self.section.layout['readableHeaders']
            table_columns = fix_order(ordered, readable_headers)
        else:
            table_columns = self.section.layout['tableColumns']

        # Quick fix, word crashes on more than MAX_MS_TABLE_COLS_LIMIT
        #   (64 right now) columns.
        # See: https://stackoverflow.com/questions/36921010/docx-does-not-support-more-than-63-columns-in-a-table
        table_columns = table_columns[0:MAX_MS_TABLE_COLS_LIMIT]

        for i, row_title in enumerate(table_columns):
            if not isinstance(row_title, str):
                table_columns.remove(row_title)

        if 'title' in self.section.extra:
            table = self.cell_object.cell.add_table(rows=2,
                                                    cols=len(table_columns))
            title = table.cell(0, 0)
            title.merge(table.cell(0, len(table_columns) - 1))
            insert_text(title, self.section.extra['title'], self.style['title'])

            hdr_cells = table.rows[1].cells
        else:
            table = self.cell_object.cell.add_table(rows=1,
                                                    cols=len(table_columns))
            hdr_cells = table.rows[0].cells

        table.style = DEFAULT_TABLE_STYLE

        if 'list_style' in self.section.extra and self.section.extra[
            'list_style']:
            table.style = None

        for i, row_title in enumerate(table_columns):
            insert_text(hdr_cells[i], row_title, self.style['text'])

        for row_item in table_data:
            row_cells = table.add_row().cells
            for i, row_title in enumerate(table_columns):
                if row_title not in row_item:
                    continue

                # Old json format can have 'Avatars', which are images
                if isinstance(row_item[row_title], dict) and \
                        row_item[row_title]['type'] == 'image':
                    insert_table_image(row_item, row_title, row_cells[i])
                else:
                    insert_text(row_cells[i], str(row_item[row_title]),
                                self.style['text'])


def invoke(cell_object, section):
    if section.type != 'table':
        err_msg = f'Called table but not table -  [{section}]'
        return utils.insert_error(cell_object, err_msg)

    TableElement(cell_object, section).insert()
