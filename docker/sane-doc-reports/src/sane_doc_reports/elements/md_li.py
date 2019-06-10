from sane_doc_reports import utils
from sane_doc_reports.populate.utils import insert_text
from sane_doc_reports.transform.markdown.MarkdownSection import MarkdownSection
from sane_doc_reports.domain.Wrapper import Wrapper
from sane_doc_reports.conf import DEBUG, MD_TYPE_LIST_ITEM, ORDERED_LIST_NAME
from sane_doc_reports.elements import markdown, error
from sane_doc_reports.utils import get_current_li


class LiWrapper(Wrapper):

    def wrap(self):
        if DEBUG:
            print("Wrapping list item...")

        p_style, list_level, list_type = get_current_li(self.section.extra,
                                                        'List Number')

        self.cell_object.add_paragraph(style=p_style)

        numbered = False
        if list_type == ORDERED_LIST_NAME:
            numbered = True

        utils.list_number(self.cell_object.cell, self.cell_object.paragraph,
                          level=list_level, num=numbered)

        if isinstance(self.section.contents, str):
            insert_text(self.cell_object, self.section.contents)
            return

        temp_section = MarkdownSection('markdown', self.section.contents, {},
                                       {})
        temp_section.propagate_extra('inline', True)

        markdown.invoke(self.cell_object, temp_section,
                        invoked_from_wrapper=True)


def invoke(cell_object, section):
    if section.type != MD_TYPE_LIST_ITEM:
        section.contents = f'Called li but not li -  [{section}]'
        return error.invoke(cell_object, section)

    LiWrapper(cell_object, section).wrap()
