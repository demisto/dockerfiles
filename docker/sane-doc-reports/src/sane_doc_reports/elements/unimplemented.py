from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG
from sane_doc_reports.elements import error, md_hr


class UnimplementedElement(Element):
    """ Used to continue generator docx even with unsupported types """

    def insert(self):
        if DEBUG:
            print('Adding unimplemented...')

        self.section.contents = f'"{self.section.type}" is not implemented' + \
                                ' in Docx yet. If required, use PDF instead'
        error.invoke(self.cell_object, self.section)


def invoke(cell_object, section) -> None:
    UnimplementedElement(cell_object, section).insert()
