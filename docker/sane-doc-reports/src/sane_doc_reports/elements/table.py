from sane_doc_reports.domain.CellObject import CellObject
from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG, PYDOCX_FONT_SIZE, \
    DEFAULT_TABLE_FONT_SIZE, DEFAULT_TABLE_STYLE, PYDOCX_FONT_NAME, \
    PYDOCX_FONT_COLOR, DEFAULT_FONT_COLOR, DEFAULT_TITLE_FONT_SIZE, \
    PYDOCX_FONT_BOLD, DEFAULT_TITLE_COLOR
from sane_doc_reports.domain.Section import Section
from sane_doc_reports.elements import error, image
from sane_doc_reports.populate.utils import insert_text
from sane_doc_reports.utils import get_chart_font


def fix_order(ordered, readable_headers) -> list:
    """ Return the readable headers by the order given """
    readable_headers_values = readable_headers.values()
    temp_readable = {
        **{i[0].lower() + i[1:]: i for i in readable_headers_values},
        **{i.lower(): i for i in readable_headers_values}}
    temp_readable = {k.replace(" ", ""): v for k, v in temp_readable.items()}

    # Old json format table columns are not lowercase
    inv_fix = {i: i for i in readable_headers_values}
    temp_readable = {**temp_readable, **inv_fix}

    # New format fix
    if any([isinstance(i, dict) for i in ordered]):
        ret = []
        for k in ordered:
            key = k.get('key')
            key = readable_headers.get(key, key)
            if key not in ret:
                ret.append(key)
        return ret

    ret = []
    for ordered_key in ordered:
        if isinstance(ordered_key, str):
            ret.append(temp_readable[ordered_key])
    return ret


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

        }
    }

    def insert(self):
        if DEBUG:
            print("Adding table...")

        table_data = self.section.contents
        if 'tableColumns' not in self.section.layout:
            return

        if isinstance(table_data, dict):
            table_data = table_data.get('data', table_data)

        # Fix new lists
        if isinstance(table_data, dict):
            wrapper_table = self.cell_object.cell.add_table(rows=2, cols=len(
                table_data.keys()))
            i = 0

            # Add the wrapping headers
            for wrapper_header, table_contents in table_data.items():
                hdr = wrapper_table.cell(0, i)
                insert_text(hdr, wrapper_header,
                            self.style['title'])
                body = wrapper_table.cell(1, i)
                c = CellObject(body)
                # Hacky but will do the job
                invoke(c, Section('table', table_contents, {}, {}))
                i += 1
            return

        if 'readableHeaders' in self.section.layout:
            ordered = self.section.layout['tableColumns']
            readable_headers = self.section.layout['readableHeaders']
            table_columns = fix_order(ordered, readable_headers)
        else:
            table_columns = self.section.layout['tableColumns']


        # Quick fix, word crashes on more than 64 columns.
        table_columns = table_columns[0:63]


        for i, header_text in enumerate(table_columns):
            if not isinstance(header_text, str):
                table_columns.remove(header_text)

        if 'title' in self.section.extra:
            table = self.cell_object.cell.add_table(rows=2,
                                                    cols=len(table_columns))
            title = table.cell(0, 0)
            title.merge(table.cell(0, len(table_columns) - 1))
            insert_text(title, self.section.extra['title'], self.style['title'])

            hdr_cells = table.rows[1].cells
        else:
            table = self.cell_object.cell.add_table(rows=2,
                                                    cols=len(table_columns))
            hdr_cells = table.rows[0].cells

        table.style = DEFAULT_TABLE_STYLE

        if 'list_style' in self.section.extra and self.section.extra[
            'list_style']:
            table.style = None

        for i, header_text in enumerate(table_columns):
            insert_text(hdr_cells[i], header_text, self.style['text'])

        if len(table_columns) > 63:
            # TODO: add error.
            pass

        for r in table_data:
            row_cells = table.add_row().cells
            for i, header_text in enumerate(table_columns):
                if header_text not in r:
                    continue

                # Old json format can have 'Avatars', which are images
                if isinstance(r[header_text], dict) and \
                        r[header_text]['type'] == 'image':
                    row_temp = r[header_text]
                    s = Section(row_temp['type'], row_temp['data'], {}, {})
                    co = CellObject(row_cells[i], add_run=False)
                    image.invoke(co, s)
                else:
                    insert_text(row_cells[i], r[header_text],
                                self.style['text'])


def invoke(cell_object, section):
    if section.type != 'table':
        section.contents = f'Called table but not table -  [{section}]'
        return error.invoke(cell_object, section)

    TableElement(cell_object, section).insert()
