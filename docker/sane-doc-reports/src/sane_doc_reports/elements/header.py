from sane_doc_reports import utils
from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG
from sane_doc_reports.populate.utils import insert_header


class HeaderElement(Element):
    """ Mainly used to fix the old json's header element """

    def insert(self):
        if DEBUG:
            print('Adding text...')

        insert_header(self.cell_object, self.section.contents, header='h1',
                      style=self.section.get_style())


def invoke(cell_object, section) -> None:
    if section.type != 'header':
        err_msg = f'Called header but not header -  [{section}]'
        return utils.insert_error(cell_object, err_msg)

    HeaderElement(cell_object, section).insert()
