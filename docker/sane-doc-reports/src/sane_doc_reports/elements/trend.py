from sane_doc_reports.domain.CellObject import CellObject
from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG, TREND_MAIN_NUMBER_FONT_SIZE, \
    ALIGN_RIGHT, TREND_SECOND_NUMBER_FONT_SIZE, PYDOCX_FONT_SIZE, \
    PYDOCX_TEXT_ALIGN
from sane_doc_reports.elements import error
from sane_doc_reports.populate.utils import insert_text


class TrendElement(Element):
    style = {
        'main': {
            PYDOCX_FONT_SIZE: TREND_MAIN_NUMBER_FONT_SIZE,
            PYDOCX_TEXT_ALIGN: ALIGN_RIGHT
        },
        'trend': {
            PYDOCX_FONT_SIZE: TREND_SECOND_NUMBER_FONT_SIZE,
            PYDOCX_TEXT_ALIGN: ALIGN_RIGHT
        },
        'title': {
            PYDOCX_FONT_SIZE: TREND_SECOND_NUMBER_FONT_SIZE,
            PYDOCX_TEXT_ALIGN: ALIGN_RIGHT
        }
    }

    def insert(self):
        if DEBUG:
            print("Adding trend...")

        table = self.cell_object.cell.add_table(rows=2, cols=4)

        # Add the main number
        current_sum = self.section.contents['currSum']
        inner_cell = table.cell(0, 1)
        main_number = CellObject(inner_cell)
        insert_text(main_number, str(current_sum), self.style['main'])

        # Add the trend number
        previous_sum = self.section.contents['prevSum']
        # Fix for the percentages
        if previous_sum == 0:
            previous_sum = 1

        change = (current_sum * 100) / previous_sum
        if change < 0:
            direction = '⏷'  # Down arrow
        elif change == 0:
            direction = '= '
        else:
            direction = '⏶'  # Up arrow

        value_percent = f'{direction}{change}%'
        inner_cell = table.cell(0, 2)
        trend_number = CellObject(inner_cell)
        insert_text(trend_number, value_percent, self.style['trend'])

        # Add the title
        third_cell = table.cell(1, 1)
        table.cell(1, 2).merge(third_cell)
        title = CellObject(third_cell)
        insert_text(title, str(self.section.extra['title']),
                    self.style['title'])


def invoke(cell_object, section):
    if section.type != 'trend':
        section.contents = f'Called trend but not trend -  [{section}]'
        return error.invoke(cell_object, section)

    TrendElement(cell_object, section).insert()
