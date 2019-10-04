from sane_doc_reports import utils
from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG


class UnimplementedElement(Element):
    """ Used to continue generator docx even with unsupported types """

    def insert(self):
        if DEBUG:
            print('Adding unimplemented...')

        err_msg = f'"{self.section.type}" is not implemented' + \
                  ' in Docx yet. If required, use PDF instead'
        utils.insert_error(self.cell_object, err_msg)


def invoke(cell_object, section) -> None:
    UnimplementedElement(cell_object, section).insert()
