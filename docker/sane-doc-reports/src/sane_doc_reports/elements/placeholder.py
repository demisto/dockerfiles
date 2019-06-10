from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG
from sane_doc_reports.elements import error, markdown
from sane_doc_reports.transform.markdown.md_helpers import \
    markdown_to_section_list


class PlaceHolderElement(Element):
    """ Mainly used to fix the old json's header element """

    def insert(self):
        if DEBUG:
            print('Adding placeholder...')

        self.section.type = 'markdown'
        self.section.contents = markdown_to_section_list(self.section.contents['text'])
        markdown.invoke(self.cell_object, self.section)


def invoke(cell_object, section) -> None:
    if section.type != 'placeholder':
        section.contents = f'Called placeholder but not placeholder -  [{section}]'
        return error.invoke(cell_object, section)

    PlaceHolderElement(cell_object, section).insert()
