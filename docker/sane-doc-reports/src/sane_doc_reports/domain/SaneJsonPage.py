from functools import reduce
from typing import List, Tuple

from sane_doc_reports.transform.positioning import get_vertical_pos, \
    get_horizontal_pos, \
    row_pos
from sane_doc_reports.conf import *


class SaneJsonPage:
    def __init__(self):
        self.sections_list = []

    def add_section(self, section_json: str):
        self.sections_list.append(section_json)

    def normalize_row_positions(self) -> None:
        # Get the minimal section's vertical position (ROW_POSITION_KEY) in page
        min_pos = row_pos(
            min(self.sections_list,
                key=lambda json_section: row_pos(json_section)))

        # Negate the minimal position from each section,
        # So when we are "normalized" each page vertical position starts form 0
        # I.e. sometimes rowPos can be something initially like 1180, and we
        # want it to be 0 (if it's the second row in that page).
        for i, section in enumerate(self.sections_list):
            self.sections_list[i][LAYOUT_KEY][ROW_POSITION_KEY] = row_pos(
                section) - min_pos

    def __len__(self) -> int:
        return len(self.sections_list)

    def get_max_vertical_position(self) -> int:
        # Note: we max with 1, in case there is an section without a height,
        # we still want a table with a size of 1 at least.

        # Sending less than 2 sections to reduce will break it
        section_list = self.sections_list
        if len(section_list) == 1:
            return max(get_vertical_pos(section_list[0]), 1)

        return max(reduce(lambda last_vertical_pos, current_section:
                          max(
                              get_vertical_pos(last_vertical_pos),
                              get_vertical_pos(current_section)
                          ), section_list), 1)

    def get_max_horizontal_position(self) -> int:

        # If we want to have a constant sized grid
        if SHOULD_HAVE_12_GRID:
            return 12

        # Note: we max with 1, in case there is an section without a height,
        # we still want a table with a size of 1 at least.

        # Sending less than 2 sections to reduce will break it
        section_list = self.sections_list
        if len(section_list) == 1:
            return max(get_horizontal_pos(section_list[0]), 1)

        return max(reduce(lambda last_horizontal, current_section:
                          max(
                              get_horizontal_pos(last_horizontal),
                              get_horizontal_pos(current_section)
                          ), section_list), 1)

    def calculate_page_grid(self) -> Tuple[int, int]:
        """
            We want to the the max cols and row values,
             to create the table for each page
        """
        rows = self.get_max_vertical_position()
        cols = self.get_max_horizontal_position()

        return cols, rows

    def get_sections(self) -> List:
        return self.sections_list
