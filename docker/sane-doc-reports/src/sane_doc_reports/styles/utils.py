from docx.shared import Pt

from sane_doc_reports.domain import CellObject
from sane_doc_reports.domain.Section import Section
from sane_doc_reports.styles.colors import name_to_rgb, hex_to_rgb
from sane_doc_reports.conf import PYDOCX_FONT_SIZE, PYDOCX_FONT_NAME, \
    PYDOCX_FONT_BOLD, PYDOCX_FONT_STRIKE, PYDOCX_FONT_UNDERLINE, \
    PYDOCX_FONT_ITALIC, PYDOCX_FONT_COLOR, PYDOCX_TEXT_ALIGN, \
    DEFAULT_WORD_FONT, ALIGN_LEFT, ALIGN_RIGHT, ALIGN_CENTER, \
    DEFAULT_FONT_DARK_COLOR, BASE_HEADER_FONT_SIZE, BASE_FONT_SIZE


def _apply_cell_styling(cell_object: CellObject, section: Section):
    style = section.get_style()

    # Font size
    if PYDOCX_FONT_SIZE in style:
        cell_object.run.font.size = Pt(style[PYDOCX_FONT_SIZE])

    # Set default font
    cell_object.run.font.name = DEFAULT_WORD_FONT

    # Font family
    if PYDOCX_FONT_NAME in style:
        cell_object.run.font.name = style[PYDOCX_FONT_NAME]

    # Other characteristics
    if PYDOCX_FONT_BOLD in style:
        cell_object.run.font.bold = style[PYDOCX_FONT_BOLD]
    if PYDOCX_FONT_STRIKE in style:
        cell_object.run.font.strike = style[PYDOCX_FONT_STRIKE]
    if PYDOCX_FONT_UNDERLINE in style:
        cell_object.run.font.underline = style[PYDOCX_FONT_UNDERLINE]
    if PYDOCX_FONT_ITALIC in style:
        cell_object.run.font.italic = style[PYDOCX_FONT_ITALIC]

    # Font color
    if PYDOCX_FONT_COLOR in style:
        if style[PYDOCX_FONT_COLOR][0] != '#':
            cell_object.run.font.color.rgb = name_to_rgb(
                style[PYDOCX_FONT_COLOR])
        else:
            cell_object.run.font.color.rgb = hex_to_rgb(
                style[PYDOCX_FONT_COLOR])

    # Paragraph styling
    if PYDOCX_TEXT_ALIGN in style:
        if style[PYDOCX_TEXT_ALIGN] == 'left':
            cell_object.paragraph.paragraph_format.alignment = ALIGN_LEFT
        elif style[PYDOCX_TEXT_ALIGN] == 'right':
            cell_object.paragraph.paragraph_format.alignment = ALIGN_RIGHT
        elif style[PYDOCX_TEXT_ALIGN] == 'center':
            cell_object.paragraph.paragraph_format.alignment = ALIGN_CENTER
        elif style[PYDOCX_TEXT_ALIGN] in [ALIGN_RIGHT, ALIGN_CENTER,
                                          ALIGN_CENTER]:
            cell_object.paragraph.paragraph_format.alignment = int(
                style[PYDOCX_TEXT_ALIGN])


def _attach_all_styles(section: Section, base_style: dict) -> Section:
    attribute_styles = {k: True for k in section.attrs}

    section.add_style(base_style, is_new=False)
    section.add_style(attribute_styles)
    return section


def insert_header_style(section: Section) -> Section:
    """ Apply header specific styles and then the default style,
        Works by getting the H{SIZE} and applying the corresponding size.
    """

    level = int(section.extra['header_tag'].replace('h', ''))
    header_font_size = BASE_HEADER_FONT_SIZE - (level - 1) * 2
    base_style = {
        "fontSize": header_font_size,
        "color": DEFAULT_FONT_DARK_COLOR
    }

    return _attach_all_styles(section, base_style)


def insert_text_style(section: Section) -> Section:
    """ Apply header specific styles and then the default style,
    """
    base_style = {
        'fontSize': BASE_FONT_SIZE,
        'color': DEFAULT_FONT_DARK_COLOR
    }
    return _attach_all_styles(section, base_style)


def apply_style(cell_object: CellObject, section: Section) -> None:
    """ Switch case to choose the right style """

    # Insert the style
    section = {
        "text": lambda section: insert_text_style(section),
        "header": lambda section: insert_header_style(section)
    }[section.type](section)

    _apply_cell_styling(cell_object, section)
