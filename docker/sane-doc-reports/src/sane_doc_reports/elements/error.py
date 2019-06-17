from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG
import sane_doc_reports.populate.utils as utils
from sane_doc_reports.styles.utils import style_cell


class ErrorElement(Element):
    """ Used to indicate errors in the elements
    (better for debugging problems in the generation)"""

    def insert(self):
        if DEBUG:
            print('Adding error element...')

        style = {
            'bold': False,
            'color': '#ff0013',
            'fontSize': 10,
            'underline': False,
            'strikethrough': False,
            'italic': False
        }

        # Add some padding
        table = self.cell_object.cell.add_table(rows=1, cols=1)
        if DEBUG:
            table.style = 'Table Grid'
        inner_cell = table.cell(0, 0)
        style_cell(inner_cell, {"top": 50, "bottom": 50})

        error_message = f'ERROR GENERATING SECTION ({self.section.contents})'
        utils.insert_text(inner_cell, error_message, style)


def invoke(cell_object, section) -> None:
    ErrorElement(cell_object, section).insert()
