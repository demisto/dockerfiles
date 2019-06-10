from sane_doc_reports.transform.markdown.MarkdownSection import MarkdownSection
from sane_doc_reports.domain.Wrapper import Wrapper
from sane_doc_reports.conf import ORDERED_LIST_NAME, DEBUG, MD_TYPE_ORDERED_LIST
from sane_doc_reports.elements import markdown, error
from sane_doc_reports.utils import get_current_li


class UlWrapper(Wrapper):

    def wrap(self):
        if DEBUG:
            print("Ol code...")

        temp_section = MarkdownSection('markdown', self.section.contents, {},
                                       {})

        p_style, list_level, list_type = get_current_li(self.section.extra,
                                                        ORDERED_LIST_NAME)

        temp_section.propagate_extra('list_level', list_level,
                                     only_multiple_children=False)
        temp_section.propagate_extra('list_type', list_type,
                                     only_multiple_children=False)

        markdown.invoke(self.cell_object, temp_section,
                        invoked_from_wrapper=True)


def invoke(cell_object, section):
    if section.type != MD_TYPE_ORDERED_LIST:
        section.contents = f'Called ol but not ol -  [{section}]'
        return error.invoke(cell_object, section)

    UlWrapper(cell_object, section).wrap()
