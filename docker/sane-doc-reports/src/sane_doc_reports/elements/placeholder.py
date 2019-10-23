from sane_doc_reports import utils
from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG
from sane_doc_reports.elements import markdown
from sane_doc_reports.transform.markdown.md_helpers import \
    markdown_to_section_list


class PlaceHolderElement(Element):
    """ Mainly used to fix the old json's header element """

    def insert(self):
        if DEBUG:
            print('Adding placeholder...')

        self.section.type = 'markdown'
        if isinstance(self.section.contents, str):
            self.section.contents = markdown_to_section_list(
                self.section.contents)
        else:
            self.section.contents = markdown_to_section_list(
                self.section.contents['text'])
        markdown.invoke(self.cell_object, self.section)


def invoke(cell_object, section) -> None:
    if section.type != 'placeholder':
        err_msg = f'Called placeholder but not placeholder -  [{section}]'
        return utils.insert_error(cell_object, err_msg)

    PlaceHolderElement(cell_object, section).insert()
