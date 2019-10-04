from sane_doc_reports import utils
from sane_doc_reports.conf import DEBUG, MD_TYPE_HORIZONTAL_LINE, \
    PYDOCX_TEXT_ALIGN, DEFAULT_HR_DASHES_SIZE
from sane_doc_reports.domain.Element import Element
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
        err_msg = f'Called hr but not hr -  [{section}]'
        return utils.insert_error(cell_object, err_msg)

    HorizontalLineElement(cell_object, section).insert()
