from sane_doc_reports.conf import DEBUG, MD_TYPE_HORIZONTAL_LINE, ALIGN_CENTER, \
    PYDOCX_TEXT_ALIGN, DEFAULT_HR_DASHES_SIZE
from sane_doc_reports.domain.Element import Element
from sane_doc_reports.elements import error
from sane_doc_reports.populate.utils import insert_text


class HorizontalLineElement(Element):

    def insert(self):
        if DEBUG:
            print('Adding horizontal line...')

        self.cell_object.add_paragraph(add_run=False)
        insert_text(self.cell_object, '⎯' * DEFAULT_HR_DASHES_SIZE,
                    style={PYDOCX_TEXT_ALIGN: 'center'})


def invoke(cell_object, section):
    if section.type != MD_TYPE_HORIZONTAL_LINE:
        section.contents = f'Called hr but not hr -  [{section}]'
        return error.invoke(cell_object, section)

    HorizontalLineElement(cell_object, section).insert()
