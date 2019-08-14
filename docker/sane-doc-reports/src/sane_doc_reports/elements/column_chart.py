import matplotlib.pyplot as plt

from sane_doc_reports import utils
from sane_doc_reports.domain.Element import Element
from sane_doc_reports.domain.Section import Section
from sane_doc_reports.conf import DEBUG, DEFAULT_BAR_WIDTH, \
    DEFAULT_BAR_ALPHA, CHART_LABEL_NONE_STRING, \
    DEFAULT_FONT_COLOR, DEFAULT_TITLE_FONT_SIZE, LEGEND_STYLE
from sane_doc_reports.elements import image, error
from sane_doc_reports.styles.colors import get_colors
from sane_doc_reports.utils import set_legend_style, remove_plot_borders, \
    get_chart_font, set_axis_font


class ColumnChartElement(Element):
    style = {
        'title': {
            'fontname': get_chart_font(),
            'color': DEFAULT_FONT_COLOR,
            'fontsize': DEFAULT_TITLE_FONT_SIZE
        }
    }

    @utils.plot
    def insert(self) -> None:
        """
        This is a standing barchart (bar goes up)
        """
        if DEBUG:
            print("Adding a column chart!")

        # Fix sizing
        size_w, size_h, dpi = utils.convert_plt_size(self.section)
        plt.figure(figsize=(size_w, size_h), dpi=dpi)

        data = self.section.contents
        objects = [i['name'] for i in data]

        y_axis = [i for i in range(len(objects))]
        x_axis = [i['data'][0] for i in data]

        colors = get_colors(self.section.layout, objects)

        rects = plt.bar(y_axis, x_axis, align='center', alpha=DEFAULT_BAR_ALPHA,
                        width=DEFAULT_BAR_WIDTH, color=colors)

        ax = plt.gca()
        remove_plot_borders(ax)

        # Fix the legend values to be "some_value (some_number)" instead of
        # just "some_value"
        ledgend_keys = [CHART_LABEL_NONE_STRING if i == '' else i for i in
                        objects]
        fixed_legends = [f'{v} ({x_axis[i]})' for i, v in
                         enumerate(ledgend_keys)]

        # Move legend
        legend_location = 'upper center'
        legend_location_relative_to_graph = (0.5, -0.35)
        a = ax.legend(rects, fixed_legends, loc=legend_location,
                      bbox_to_anchor=legend_location_relative_to_graph,
                      handlelength=0.7)

        set_legend_style(a, self.section.layout[LEGEND_STYLE])

        ax.set_xlim(-len(objects), len(objects))

        set_axis_font(ax)
        plt.xticks(y_axis, objects)
        plt.title(self.section.extra['title'], **self.style['title'])

        plt_b64 = utils.plt_t0_b64(plt)

        s = Section('image', plt_b64, {}, {})
        image.invoke(self.cell_object, s)


def invoke(cell_object, section):
    if section.type != 'column_chart':
        section.contents = 'Called column_chart but not column_chart - ' + \
                           f'[{section}]'
        return error.invoke(cell_object, section)

    ColumnChartElement(cell_object, section).insert()
