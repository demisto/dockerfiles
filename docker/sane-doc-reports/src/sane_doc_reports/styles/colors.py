from docx.shared import RGBColor
from matplotlib import colors as mcolors

colors = dict(mcolors.BASE_COLORS, **mcolors.CSS4_COLORS)
DEFAULT_BAR_COLOR = '#999999'
CHART_COLORS = ['#E57373', '#FF1D1E', '#FF5000', '#E55100', '#D74315',
                '#F06292', '#FF3F81', '#F50057', '#C2195B', '#E91D63',
                '#AD1457', '#CE93D8', '#EA80FC', '#FA99D0', '#FD5BDE',
                '#D500F9', '#AA00FF', '#BA68C8', '#B287FE', '#9575CD',
                '#AB47BC', '#8E24AA', '#8052F3', '#9FA8DA', '#7C71F5',
                '#536DFE', '#5C6BC0', '#3F51B5', '#6200EA', '#A3C9FF',
                '#64B5F6', '#03B0FF', '#2196F3', '#2979FF', '#295AFF',
                '#B7E7FF', '#81D4FA', '#80DEEA', '#00B8D4', '#039BE5',
                '#0277BD', '#1AEADE', '#18DEE5', '#00E5FF', '#4DD0E1',
                '#4DB6AC', '#0097A7', '#0097A7', '#64DC17', '#00E676',
                '#00C853', '#20B358', '#4CAF50', '#C5FE01', '#ADE901',
                '#50EB07', '#AED581', '#8BC34A', '#69A636', '#EDFE41',
                '#FFEA00', '#FFD740', '#F9A825', '#FB8C00', '#FF7500',
                '#DBDBDB', '#CFD8DC', '#9EB6C3', '#B2B7B9', '#989898',
                '#90A4AE']


def name_to_rgb(color_name: str):
    hex_color = name_to_hex(color_name)
    return hex_to_rgb(hex_color)


def name_to_hex(color_name: str):
    """ Get the hex representation of a color name (CSS4) """
    return colors[color_name].lower()


def hex_to_rgb(hex_color: str):
    """
    Convert a hex color string into an RGBColor object (used in python-elements)
    """
    hex_color = hex_color.lstrip('#')
    return RGBColor(*[int(hex_color[i:i + 2], 16) for i in (0, 2, 4)])


def _get_chart_color(value):
    """ Trying to copy the sane-report color scheme """

    def _hash_simple_value(s):
        """ djb2 """
        current_hash = 5381
        i = len(s)
        for _ in s:
            i = i - 1
            current_hash = (current_hash * 33) ^ ord(s[i])
        return current_hash & 0xFFFFFFFF

    if not value:
        return DEFAULT_BAR_COLOR

    index = _hash_simple_value(value) % len(CHART_COLORS)
    return CHART_COLORS[index]


def get_colors(section_layout, objects):
    """ Return the chart colors and replace the default colors if they
    are hardcoded """
    default_colors = [_get_chart_color(i) for i in objects]
    if "legend" not in section_layout or not isinstance(
            section_layout['legend'], list):
        return default_colors

    legend_colors = section_layout['legend']
    defined_colors = [i['name'] for i in legend_colors]
    ret_colors = []
    for name in objects:
        if name in defined_colors:
            ret_colors.append(
                legend_colors[defined_colors.index(name)]['color'])
        else:
            ret_colors.append(default_colors.pop())
    return ret_colors
