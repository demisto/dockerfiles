from arrow.parser import ParserError
from pyquery import PyQuery

from sane_doc_reports import utils
from sane_doc_reports.populate.utils import insert_text, insert_header
from sane_doc_reports.transform.markdown.MarkdownSection import MarkdownSection
from sane_doc_reports.conf import MD_TYPE_DIV, MD_TYPE_CODE, MD_TYPE_QUOTE, \
    MD_TYPE_UNORDERED_LIST, MD_TYPE_ORDERED_LIST, MD_TYPE_LIST_ITEM, \
    MD_TYPE_HORIZONTAL_LINE, MD_TYPE_IMAGE, MD_TYPE_LINK, MD_TYPE_TEXT, \
    MD_TYPE_INLINE_TEXT, MD_TYPES_HEADERS, MD_TYPE_TABLE, SHOULD_NEW_LINE, \
    MD_ETC_WRAPPERS, DEBUG
from sane_doc_reports.elements import md_code, md_ul, md_li, \
    md_blockquote, \
    md_hr, md_ol, md_link, md_image, table
from sane_doc_reports.domain import CellObject
from sane_doc_reports.domain.Section import Section
from sane_doc_reports.domain.Wrapper import Wrapper
from sane_doc_reports.utils import get_formatted_date


class MarkdownWrapper(Wrapper):

    def wrap(self, invoked_from_wrapper=False):
        # Handle called from another wrapper.
        md_section_list = None
        if isinstance(self.section.contents, list):
            md_section_list = self.section.contents

        elif invoked_from_wrapper and \
                isinstance(self.section.contents.contents, str):
            md_section_list = [self.section.contents]

        if not isinstance(md_section_list, list):
            raise ValueError('Markdown section does not have valid contents ' +
                             '(must be a list)')

        for section in md_section_list:
            # === Start wrappers ===
            if section.type == MD_TYPE_DIV:
                temp_section = MarkdownSection('markdown', section.contents,
                                               {}, {})
                invoke(self.cell_object, temp_section)
                continue

            if section.type == MD_TYPE_CODE:
                md_code.invoke(self.cell_object, section)
                self.cell_object.update_paragraph()
                continue

            if section.type == MD_TYPE_QUOTE:
                md_blockquote.invoke(self.cell_object, section)
                self.cell_object.update_paragraph()
                continue

            if section.type == MD_TYPE_UNORDERED_LIST:
                md_ul.invoke(self.cell_object, section)
                self.cell_object.update_paragraph()
                continue

            if section.type == MD_TYPE_ORDERED_LIST:
                md_ol.invoke(self.cell_object, section)
                self.cell_object.update_paragraph()
                continue

            if section.type == MD_TYPE_LIST_ITEM:
                md_li.invoke(self.cell_object, section)
                continue

            if section.type == MD_TYPE_TABLE:
                table_html = section.extra['original_html']
                t = PyQuery(table_html)
                headers = [i.find('th') for i in t.find('tr').items()][0]
                headers = [c.text() for c in headers.items()]

                rows = [i.find('td') for i in t.find('tr').items() if
                        i.find('td')]
                data = []
                for row in rows:
                    r = {headers[i]: c.text() for i, c in
                         enumerate(row.items())}
                    data.append(r)
                s = Section("table", data, {"tableColumns": headers}, {})
                table.invoke(self.cell_object, s)
                continue

            # Fix wrapped:
            #   (Some times there are elements which contain other elements,
            #    but are not considered one of the declared wrappers)
            # They are in MD_ETC_WRAPPERS.
            if isinstance(section.contents,
                          list) and section.type in MD_ETC_WRAPPERS:
                is_inside_wrapper = False

                if 'inline' in section.extra:
                    is_inside_wrapper = True

                if section.type == 'span':
                    section.propagate_extra('check_newline', True,
                                            only_multiple_children=False)

                # TODO: Fix problem with H1 no newline even if in span.
                temp_section = MarkdownSection('markdown', section.contents,
                                               {}, section.extra, section.attrs)
                invoke(self.cell_object, temp_section,
                       invoked_from_wrapper=is_inside_wrapper)
                continue

            # === Elements ===
            if section.type in SHOULD_NEW_LINE and section.get_extra(
                    'check_newline'):
                self.cell_object.add_paragraph()

            if section.type == MD_TYPE_HORIZONTAL_LINE:
                md_hr.invoke(self.cell_object, section)
                continue

            # Add a block (newline) if not called from a wrapper
            #  (Should come after hr)
            if not invoked_from_wrapper:
                self.cell_object.add_paragraph()

            if section.type in MD_TYPES_HEADERS:
                # We want to keep the h{1...6} for styling
                insert_header(self.cell_object, section.contents,
                              header=section.type, style=section.get_style())

                continue

            if section.type in [MD_TYPE_TEXT, MD_TYPE_INLINE_TEXT]:
                if invoked_from_wrapper:
                    self.cell_object.add_run()

                if not section.contents:
                    continue

                if '{date}' in section.contents:
                    try:
                        formatted_date = get_formatted_date(
                            '',
                            section.layout)
                    except ParserError as e:
                        formatted_date = 'n/a'
                    section.contents = section.contents.replace('{date}',
                                                                formatted_date)

                insert_text(self.cell_object, section)
                continue

            if section.type == MD_TYPE_LINK:
                md_link.invoke(self.cell_object, section)
                continue

            if section.type == MD_TYPE_IMAGE:
                md_image.invoke(self.cell_object, section)
                continue

            if DEBUG:
                raise ValueError(f'Section type is not defined: {section.type}')
            # If we couldn't find it, just ignore the tag.


def invoke(cell_object: CellObject, section: Section,
           invoked_from_wrapper=False):
    if section.type != 'markdown':
        err_msg = f'Called markdown but not markdown -  [{section}]'
        return utils.insert_error(cell_object, err_msg)

    MarkdownWrapper(cell_object, section).wrap(
        invoked_from_wrapper=invoked_from_wrapper)
