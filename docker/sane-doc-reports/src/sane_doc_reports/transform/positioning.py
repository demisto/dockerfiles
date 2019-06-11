from typing import Union

from sane_doc_reports.conf import *
from sane_doc_reports.domain.Section import Section


def row_pos(section: Union[Section, dict]) -> int:
    if isinstance(section, dict):
        return section[LAYOUT_KEY][ROW_POSITION_KEY]

    return section.layout[ROW_POSITION_KEY]


def col_pos(section: Union[Section, dict]) -> int:
    if isinstance(section, dict):
        return section[LAYOUT_KEY][COL_POSITION_KEY]

    return section.layout[COL_POSITION_KEY]


def get_height(section: Union[Section, dict]) -> int:
    """ Get the relative (to the grid) height of the section """
    if isinstance(section, dict):
        return section[LAYOUT_KEY][HEIGHT_POSITION_KEY]

    return section.layout[HEIGHT_POSITION_KEY]


def get_width(section: Union[Section, dict]) -> int:
    """ Get the relative (to the grid) width of the section """
    if isinstance(section, dict):
        return section[LAYOUT_KEY][WIDTH_POSITION_KEY]

    return section.layout[WIDTH_POSITION_KEY]


def get_vertical_pos(section: Section) -> int:
    """ Returns the element's bottommost position """
    # Because this function is called from reduce, it might send an int
    if isinstance(section, int):
        return section
    return row_pos(section) + get_height(section)


def get_horizontal_pos(section: Section) -> int:
    """ Returns the element's rightmost position """
    # Because this function is called from reduce, it might send an int
    if isinstance(section, int):
        return section
    return col_pos(section) + get_width(section)
