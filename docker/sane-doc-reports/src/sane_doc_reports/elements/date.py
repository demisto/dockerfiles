from arrow.parser import ParserError

from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG
from sane_doc_reports.elements import error
from sane_doc_reports.populate.utils import insert_text
from sane_doc_reports.utils import get_formatted_date


class DateElement(Element):
    """ Mainly used to fix the old json's date element """

    def insert(self):
        if DEBUG:
            print('Adding date...')

        try:
            formatted_date = get_formatted_date(self.section.contents,
                                                self.section.layout)
        except ParserError as e:
            formatted_date = 'n/a'

        insert_text(self.cell_object, formatted_date)


def invoke(cell_object, section) -> None:
    if section.type != 'date':
        section.contents = f'Called date but not date -  [{section}]'
        return error.invoke(cell_object, section)

    DateElement(cell_object, section).insert()
