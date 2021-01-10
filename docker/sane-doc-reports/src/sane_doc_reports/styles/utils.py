from docx.oxml import parse_xml, OxmlElement
from docx.shared import Pt
from docx.table import _Cell
from docx.oxml.ns import nsdecls, qn

from sane_doc_reports.domain import CellObject
from sane_doc_reports.domain.Section import Section
from sane_doc_reports.styles.colors import name_to_rgb, hex_to_rgb, name_to_hex
from sane_doc_reports.conf import PYDOCX_FONT_SIZE, PYDOCX_FONT, \
    PYDOCX_FONT_BOLD, PYDOCX_FONT_STRIKE, PYDOCX_FONT_UNDERLINE, \
    PYDOCX_FONT_ITALIC, PYDOCX_FONT_COLOR, PYDOCX_TEXT_ALIGN, \
    DEFAULT_WORD_FONT, ALIGN_LEFT, ALIGN_RIGHT, ALIGN_CENTER, \
    DEFAULT_FONT_COLOR, BASE_HEADER_FONT_SIZE, BASE_FONT_SIZE, \
    DEFAULT_COLORED_CELL_COLOR, PYDOCX_BACKGROUND_COLOR


def _apply_cell_styling(cell_object: CellObject, section: Section):
    style = section.get_style()

    # Font size
    if PYDOCX_FONT_SIZE in style:
        cell_object.run.font.size = Pt(style[PYDOCX_FONT_SIZE])

    # Set default font
    cell_object.run.font.name = DEFAULT_WORD_FONT

    # Font family
    if PYDOCX_FONT in style:
        cell_object.run.font.name = style[PYDOCX_FONT]

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

    # Background color
    if 'backgroundColor' in style:
        cell_object.cell = insert_cell_background(
            cell_object.cell,
            style[PYDOCX_BACKGROUND_COLOR])

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
        "color": DEFAULT_FONT_COLOR
    }

    return _attach_all_styles(section, base_style)


def insert_text_style(section: Section) -> Section:
    """ Apply header specific styles and then the default style,
    """
    base_style = {
        'fontSize': BASE_FONT_SIZE,
        'color': DEFAULT_FONT_COLOR
    }
    return _attach_all_styles(section, base_style)


def style_cell(cell: _Cell, margins={}, color_hex=''):
    insert_cell_background(cell, color_hex)
    set_cell_margins(cell, margins)
    add_border(cell)


def add_border(cell: _Cell):
    '''
    <w:tcPr>
    <w:tcBorders>
    <w:top w:val="double" w:sz="24" w:space="0" w:color="FF0000">
    <w:start w:val="double" w:sz="24" w:space="0" w:color="FF0000">
    <w:bottom w:val="double" w:sz="24" w:space="0" w:color="FF0000">
    <w:end w:val="double" w:sz="24" w:space="0" w:color="FF0000">
    <w:tl2br w:val="double" w:sz="24" w:space="0" w:color="FF0000">
    </w:tcBorders>
    <w:tcPr>
    '''
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcBorders')

    for k in ['top', 'start', 'bottom', 'end']:
        node = OxmlElement(f'w:{k}')
        node.set(qn('w:val'), 'inset')
        node.set(qn('w:sz'), '87')
        node.set(qn('w:color'), DEFAULT_COLORED_CELL_COLOR)
        tcMar.append(node)

    tcPr.append(tcMar)


def insert_cell_background(cell: _Cell,
                           color_hex=DEFAULT_COLORED_CELL_COLOR) -> _Cell:
    """ Add a background color to a cell, from hex color """
    shading_elm_1 = parse_xml(
        f'<w:shd {nsdecls("w")} w:fill="{color_hex}"/>')
    cell._tc.get_or_add_tcPr().append(shading_elm_1)

    return cell


def apply_style(cell_object: CellObject, section: Section) -> None:
    """ Switch case to choose the right style """

    # Insert the style
    section = {
        "text": lambda section: insert_text_style(section),
        "header": lambda section: insert_header_style(section)
    }[section.type](section)

    _apply_cell_styling(cell_object, section)


def set_cell_margins(cell: _Cell, margins):
    """
    margins{top:, start:, bottom:, end:} sizes in Pt
    """
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')

    for k, m in margins.items():
        node = OxmlElement(f'w:{k}')
        node.set(qn('w:w'), str(m))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)

    tcPr.append(tcMar)
