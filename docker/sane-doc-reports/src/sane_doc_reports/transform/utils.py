import json
from collections import defaultdict
from typing import List

from sane_doc_reports.conf import LAYOUT_KEY, ROW_POSITION_KEY, \
    COL_POSITION_KEY, HEIGHT_POSITION_KEY, WIDTH_POSITION_KEY, DATA_KEY, \
    OLD_JSON_FORMAT_GRID_MAX, BASE_FONT_SIZE, DEFAULT_COLORED_CELL_COLOR, \
    PYDOCX_BACKGROUND_COLOR
from sane_doc_reports.domain.Section import sane_to_section
from sane_doc_reports.transform.markdown.md_helpers import \
    markdown_to_section_list


def transform_section(sane_section: dict):
    section = sane_to_section(sane_section)

    if section.type == 'markdown':
        section.contents = markdown_to_section_list(section.contents)

    return section


def _font_transformations(json_item: dict) -> dict:
    font_size_mapping = {
        28: 16,
        22: 20,
        16: 10,
        14: 9,
        12: 8,
    }
    if LAYOUT_KEY not in json_item:
        return json_item

    if 'style' not in json_item[LAYOUT_KEY]:
        return json_item

    if 'fontSize' not in json_item[LAYOUT_KEY]['style']:
        return json_item

    font_size = json_item[LAYOUT_KEY]['style']['fontSize']

    if font_size not in font_size_mapping:
        json_item[LAYOUT_KEY]['style']['fontSize'] = BASE_FONT_SIZE
    else:
        json_item[LAYOUT_KEY]['style']['fontSize'] = font_size_mapping[
            font_size]

    return json_item


def general_json_fixes(json_data: List[dict]) -> List[dict]:
    """ Fixes general probelms that may arise in the json
    (not necessarily related to the old format) """

    # Fix null values in the col / row positions
    for i in range(len(json_data)):
        if not json_data[i][LAYOUT_KEY][ROW_POSITION_KEY]:
            json_data[i][LAYOUT_KEY][ROW_POSITION_KEY] = 0
        if not json_data[i][LAYOUT_KEY][COL_POSITION_KEY]:
            json_data[i][LAYOUT_KEY][COL_POSITION_KEY] = 0
        if not json_data[i][DATA_KEY]:
            json_data[i][DATA_KEY] = []
        if json_data[i]['type'] in ['markdown', 'text', 'header'] \
                and ('text' not in json_data[i][DATA_KEY] or isinstance(
            json_data[i][DATA_KEY], str)):

            json_data[i][DATA_KEY] = {
                'text': json_data[i][DATA_KEY]}
        if json_data[i]['type'] == 'globalSection':
            json_data[i]['type'] = 'elem_list'
            json_data[i][DATA_KEY] = general_json_fixes(
                json_data[i][DATA_KEY])
            continue

    return json_data


def transform_old_json_format(json_data: List[dict]) -> List[dict]:
    """ Fixes all of the old json format, trying to convert
        it to the new json format.
    """

    # Fix the first element
    json_data[0][LAYOUT_KEY][ROW_POSITION_KEY] = 0
    json_data[0][LAYOUT_KEY][COL_POSITION_KEY] = 0

    # Remove unnecessary first elements (logo/side image)
    # We need to do this before we calculate the rowPos
    if json_data[0]['type'] == 'image':
        del json_data[0]
    if json_data[0]['type'] == 'logo':
        del json_data[0]
    if json_data[0]['type'] == 'logo':
        del json_data[0]

    # Normalize the rowPos
    json_data.sort(key=lambda item: item[LAYOUT_KEY][ROW_POSITION_KEY])

    # Group for columnPos normalizing (has to be after sorting)
    row_groups = defaultdict(list)
    for i, v in enumerate(json_data):
        row_groups[v[LAYOUT_KEY][ROW_POSITION_KEY]].append(
            {"original_key": i, "section": v})

    # Normalize the columnPos & rowPos by the groups
    currentRow = 0
    for row in row_groups:
        group = row_groups[row]
        width = max(int(OLD_JSON_FORMAT_GRID_MAX / len(group)), 1)
        current_width = 0
        normalized_cols = [i for i in range(len(group))]
        for i, v in enumerate(group):
            section = v['section']

            # Fix the rowPos
            section[LAYOUT_KEY][ROW_POSITION_KEY] = currentRow

            # Fix the columnPos
            section[LAYOUT_KEY][COL_POSITION_KEY] = normalized_cols[
                                                        i] * current_width
            current_width = width

            if width + normalized_cols[i] > OLD_JSON_FORMAT_GRID_MAX:
                width = max(
                    OLD_JSON_FORMAT_GRID_MAX - (normalized_cols[i] + width), 1)
            section[LAYOUT_KEY][WIDTH_POSITION_KEY] = width

            json_data[v['original_key']] = section
        currentRow += 1

    # Remove any 'automation' type (not usable here)
    json_data = [a for a in json_data if a['type'] != 'automation']

    # Fix the rowPos and add height + width
    for i in range(0, len(json_data)):

        # We need to add widths and heights, old format doesn't have them
        if HEIGHT_POSITION_KEY not in json_data[i][LAYOUT_KEY]:
            json_data[i][LAYOUT_KEY][HEIGHT_POSITION_KEY] = 1
        if WIDTH_POSITION_KEY not in json_data[i][LAYOUT_KEY]:
            json_data[i][LAYOUT_KEY][WIDTH_POSITION_KEY] = 1

        # Fix font-size
        json_data[i] = _font_transformations(json_data[i])

        # Fix nil data
        if DATA_KEY not in json_data[i] or not json_data[i][DATA_KEY]:
            json_data[i][DATA_KEY] = ""

        if json_data[i]['type'] == 'logo':
            json_data[i]['type'] = 'image'
            continue

        if json_data[i]['type'] in ['header', 'divider', 'markdown',
                                    'globalSection']:
            json_data[i][LAYOUT_KEY][WIDTH_POSITION_KEY] = 10

        if json_data[i]['type'] == 'header':
            json_data[i][LAYOUT_KEY]['style'][
                PYDOCX_BACKGROUND_COLOR] = DEFAULT_COLORED_CELL_COLOR

        if json_data[i]['type'] == 'chart':
            if 'title' not in json_data[i]:
                json_data[i]['title'] = ''

        if json_data[i]['type'] == 'table':
            if 'tableColumns' not in json_data[i]['layout']:
                table_data = json.loads(json_data[i]['data'])
                json_data[i][DATA_KEY] = table_data
                headers = list(table_data[0].keys())
                json_data[i][LAYOUT_KEY]['tableColumns'] = headers
                continue

        if json_data[i]['type'] == 'globalSection':
            json_data[i]['type'] = 'elem_list'
            json_data[i][DATA_KEY] = transform_old_json_format(
                json_data[i][DATA_KEY])
            continue

        if json_data[i]['type'] in ['markdown', 'text', 'header'] \
                and 'text' not in json_data[i][DATA_KEY]:
            json_data[i][DATA_KEY] = {
                'text': json_data[i][DATA_KEY]}

    return json_data
