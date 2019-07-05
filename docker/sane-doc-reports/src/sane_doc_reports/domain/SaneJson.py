from typing import List

from sane_doc_reports.transform.json_schema import validate
from sane_doc_reports.transform.positioning import *
from sane_doc_reports.domain.SaneJsonPage import SaneJsonPage


def _is_page_separator(json_section: dict):
    if LAYOUT_KEY not in json_section:
        return False
    if STYLE_KEY not in json_section[LAYOUT_KEY]:
        return False
    if PAGEBREAK_KEY not in json_section[LAYOUT_KEY][STYLE_KEY]:
        return False

    return json_section[LAYOUT_KEY][STYLE_KEY][PAGEBREAK_KEY] == "always"


class SaneJson:
    def __init__(self, json_data: dict) -> None:
        self.json_data = json_data
        self._verify_sane_json()
        self.sane_pages = self._separate_pages()

    def _verify_sane_json(self):
        return validate(self.json_data)

    def _separate_pages(self) -> List[SaneJsonPage]:
        """
        A sane page is a list of dicts (each dict is an section in the page),
        sections in the page are sorted by the ROW_POSITION_KEY.
        """

        # Let's sort the report by from the top downwards (by ROW_POSITION_KEY)
        report_json_sorted = sorted(self.json_data,
                                    key=lambda k: row_pos(k))

        # Let's split by any page break
        sane_pages = []
        current_page = SaneJsonPage()

        # Split the sections into pages
        for index, json_section in enumerate(report_json_sorted):

            # Check if we hit a page break
            # (add to current page and start a new one)
            if _is_page_separator(json_section):
                sane_pages.append(current_page)
                current_page = SaneJsonPage()

            current_page.add_section(json_section)

            # Check if we get the end of the sections
            if index == len(report_json_sorted) - 1:
                sane_pages.append(current_page)

        # Normalize all of the vertical positions
        # and fix order for merge, see @merge_cells
        for sane_page in sane_pages:
            sane_page.normalize_row_positions()

        return sane_pages

    def get_sane_page(self, page_index: int) -> SaneJsonPage:
        return self.sane_pages[page_index]

    def get_sane_pages(self):
        for sane_page in self.sane_pages:
            yield sane_page
