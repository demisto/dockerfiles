from typing import List

from docx.table import Table, _Cell

from sane_doc_reports.domain import Section
from sane_doc_reports.transform.positioning import row_pos, col_pos, get_height, \
    get_width


def merge_cells(grid: Table, section: Section) -> None:
    """
    Merge the sections cell using it's width and height.
    """
    row, col = row_pos(section), col_pos(section)
    width, height = get_width(section), get_height(section)

    grid.cell(row, col).merge(grid.cell(row + height - 1, col + width - 1))


def get_cell(table: Table, section: Section) -> _Cell:
    """
    Get the sections corresponding cell
    """
    row, col = row_pos(section), col_pos(section)
    return table.rows[row].cells[col]


def get_vtable_merged(table: Table) -> List[List]:
    """
    Return a virtual representation of a table. Make merged cells  0
    and normal cells 1.

    For example:
    +-----+--+--+
    |     |  |  |
    +     +--+--+
    |     |  |  |
    +-----+--+--+
    |  |  |     |
    +--+--+-----+
    Will result:
    [
        [1, 0, 1, 1],
        [0, 0, 1, 1],
        [1, 1, 1, 0]
    ]
    (<0,0> up to <2,2,> are merged as well as <3,3> up to <4,3>)

    Note 1: To understand this:
        You should probably create a table via `python-elements` and try to use
        this on it, also to trigger the `1 not in vtables` you need to fully
        merge 2 rows.

    Note 2: ._tc is the original object in python-elements, it helps us find out
        if 2 cells are the same cells or not (after merging them). So we will
        know
    """
    vtable = []
    last_cells = []

    for row in table.rows:
        # Fix zero rows
        if len(vtable) > 0:
            if 1 not in vtable[-1]:
                del vtable[-1]

        vtable.append([])
        for cell in row.cells:
            # Skip merged
            if cell._tc in last_cells:
                vtable[-1].append(0)
                continue

            vtable[-1].append(1)
            last_cells.append(cell._tc)
    return vtable
