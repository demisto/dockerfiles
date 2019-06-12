from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG
import sane_doc_reports.populate.utils as utils


class ErrorElement(Element):
    """ Used to indicate errors in the elements
    (better for debugging problems in the generation)"""

    def insert(self):
        if DEBUG:
            print('Adding error element...')

        style = {
            'bold': True,
            'color': '#ff0013',
            'fontSize': 10,
            'underline': False,
            'strikethrough': False,
            'italic': False
        }

        error_message = f'ERROR GENERATING SECTION ({self.section.contents})'
        utils.insert_text(self.cell_object, error_message, style)


def invoke(cell_object, section) -> None:
    ErrorElement(cell_object, section).insert()
