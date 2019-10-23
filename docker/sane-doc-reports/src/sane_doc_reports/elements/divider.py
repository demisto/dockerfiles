from sane_doc_reports import utils
from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG
from sane_doc_reports.elements import md_hr


class DividerElement(Element):
    """ Mainly used to fix the old json's divider element """

    def insert(self):
        if DEBUG:
            print('Adding divider...')

        self.section.type = 'hr'
        md_hr.invoke(self.cell_object, self.section)


def invoke(cell_object, section) -> None:
    if section.type != 'divider':
        err_msg = f'Called divider but not divider -  [{section}]'
        return utils.insert_error(cell_object, err_msg)

    DividerElement(cell_object, section).insert()
