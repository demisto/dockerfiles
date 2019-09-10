from math import floor

from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG, DEFAULT_DURATION_TITLE, \
    PYDOCX_FONT_SIZE, DEFAULT_DURATION_TITLE_FONT_SIZE, \
    DEFAULT_DURATION_FONT_SIZE, \
    DEFAULT_DURATION_LABEL_FONT_SIZE, DURATION_MINUTES_LABEL, \
    DURATION_HOURS_LABEL, DURATION_DAYS_LABEL, PYDOCX_TEXT_ALIGN
from sane_doc_reports.elements import error
from sane_doc_reports.populate.utils import insert_text
from sane_doc_reports.styles.utils import set_cell_margins, style_cell


def format_number(num):
    return ('0' + str(num))[-2:]


class DurationElement(Element):
    style = {
        'title': {
            PYDOCX_FONT_SIZE: DEFAULT_DURATION_TITLE_FONT_SIZE
        },
        'duration': {
            PYDOCX_FONT_SIZE: DEFAULT_DURATION_FONT_SIZE,
            PYDOCX_TEXT_ALIGN: 'center'
        },
        'label': {
            PYDOCX_FONT_SIZE: DEFAULT_DURATION_LABEL_FONT_SIZE
        }
    }

    def insert(self):
        if DEBUG:
            print("Adding duration...")

        contents = self.section.contents

        days = '0'
        hours = '0'
        minutes = '0'
        if contents:
            result = 0
            if len(contents) > 0 and isinstance(contents[0]['data'],
                                                list) and len(
                contents[0]['data']) > 0:
                result = contents[0]['data'][0]

            days = floor(result / (3600 * 24))
            result -= days * 3600 * 24

            hours = floor(result / 3600)
            result -= hours * 3600

            minutes = floor(result / 60)

            days = format_number(days)
            hours = format_number(hours)
            minutes = format_number(minutes)

        # Split the table as so:
        # +---------------+
        # | Title         |
        # +---------------+
        # | H |:| M |:| S |
        # +---+-+---+-+---+
        # .cell(row, col)
        set_cell_margins(self.cell_object.cell, {"top": 50})
        table = self.cell_object.cell.add_table(rows=2, cols=5)
        if DEBUG:
            table.style = 'Table Grid'

        title_cell = table.cell(0, 0)
        style_cell(title_cell)
        title_cell.merge(table.cell(0, 4))

        title = DEFAULT_DURATION_TITLE

        if 'title' in self.section.extra:
            title = self.section.extra['title']
        elif len(contents) > 0 and 'name' in contents[0] and contents[0][
            'name'] != '':
            title = contents['data']['name']

        insert_text(title_cell, title, self.style['title'])

        # Days
        days_cell = table.cell(1, 0)
        style_cell(days_cell)
        insert_text(days_cell, days, self.style['duration'])
        insert_text(days_cell, DURATION_DAYS_LABEL, self.style['label'],
                    add_run=True)

        # Add first colon
        colon_right = table.cell(1, 1)
        style_cell(colon_right)
        insert_text(colon_right, ':', self.style['duration'])

        # Hours
        hours_cell = table.cell(1, 2)
        style_cell(hours_cell)
        insert_text(hours_cell, hours, self.style['duration'])
        insert_text(hours_cell, DURATION_HOURS_LABEL, self.style['label'],
                    add_run=True)

        # Add second colon
        colon_left = table.cell(1, 3)
        style_cell(colon_left)
        insert_text(colon_left, ':', self.style['duration'])

        # Minutes
        minutes_cell = table.cell(1, 4)
        style_cell(minutes_cell)
        insert_text(minutes_cell, minutes, self.style['duration'], add_run=True)
        insert_text(minutes_cell, DURATION_MINUTES_LABEL, self.style['label'],
                    add_run=True)


def invoke(cell_object, section):
    if section.type != 'duration':
        section.contents = f'Called duration but not duration -  [{section}]'
        return error.invoke(cell_object, section)

    DurationElement(cell_object, section).insert()
