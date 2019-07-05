import matplotlib.pyplot as plt

from sane_doc_reports.domain.Element import Element
from sane_doc_reports import utils
from sane_doc_reports.domain.Section import Section
from sane_doc_reports.conf import DEBUG, \
    DEFAULT_BAR_WIDTH, DEFAULT_BAR_ALPHA, CHART_LABEL_NONE_STRING, \
    X_AXIS_PADDING, DEFAULT_FONT_COLOR, \
    DEFAULT_TITLE_FONT_SIZE

from sane_doc_reports.elements import image, error
from sane_doc_reports.styles.colors import get_colors
from sane_doc_reports.utils import remove_plot_borders, set_legend_style, \
    get_chart_font, set_axis_font


class BarChartElement(Element):
    style = {
        'title': {
            'fontname': get_chart_font(),
            'color': DEFAULT_FONT_COLOR,
            'fontsize': DEFAULT_TITLE_FONT_SIZE
        }
    }

    def insert(self):
        """
            This is a bar chart on the side (bar goes right)
        """

        if DEBUG:
            print("Adding a bar chart")

        # Fix sizing
        size_w, size_h, dpi = utils.convert_plt_size(self.section)
        plt.figure(figsize=(size_w, size_h), dpi=dpi)

        data = self.section.contents
        objects = [i['name'] for i in data]

        y_axis = [i for i in range(len(objects))]
        x_axis = [i['data'][0] for i in data]

        colors = get_colors(self.section.layout, objects)

        rects = plt.barh(y_axis, width=x_axis, align='center',
                         alpha=DEFAULT_BAR_ALPHA,
                         color=colors,
                         height=DEFAULT_BAR_WIDTH)

        # Fix the legend values to be "some_value (some_number)" instead of
        # just "some_value"
        ledgend_keys = [CHART_LABEL_NONE_STRING if i == '' else i for i in
                        objects]
        fixed_legends = [f'{v} ({x_axis[i]})' for i, v in
                         enumerate(ledgend_keys)]

        # Create and move the legend outside
        ax = plt.gca()
        remove_plot_borders(ax)
        legend_location = 'upper center'
        legend_location_relative_to_graph = (0.5, -0.35)

        a = ax.legend(rects, fixed_legends, loc=legend_location,
                      bbox_to_anchor=legend_location_relative_to_graph,
                      handlelength=0.7)

        set_legend_style(a)

        # Fix the axises
        set_axis_font(ax)
        ax.set_yticks(y_axis)
        ax.set_yticklabels([])
        ax.invert_yaxis()  # labels read top-to-bottom
        ax.set_xlabel('')

        # Fix the xaxis ratio to fit biggest element
        if x_axis:
            ax.set_xlim(0, max(x_axis) + X_AXIS_PADDING)

        # Remove the bottom labels
        plt.tick_params(bottom='off')
        plt.title(self.section.extra['title'], **self.style['title'])

        plt_b64 = utils.plt_t0_b64(plt)

        s = Section('image', plt_b64, {}, {})
        image.invoke(self.cell_object, s)


def invoke(cell_object, section):
    if section.type != 'bar_chart':
        section.contents = f'Called bar_chart but not bar_chart -  [{section}]'
        return error.invoke(cell_object, section)

    BarChartElement(cell_object, section).insert()
