import matplotlib.pyplot as plt

from sane_doc_reports.domain.Element import Element
from sane_doc_reports import utils
from sane_doc_reports.domain.Section import Section
from sane_doc_reports.conf import DEBUG, \
    DEFAULT_BAR_WIDTH, DEFAULT_BAR_ALPHA, CHART_LABEL_NONE_STRING, \
    X_AXIS_PADDING, DEFAULT_FONT_COLOR, \
    DEFAULT_TITLE_FONT_SIZE, PYDOCX_FONT_NAME, PYDOCX_FONT_COLOR, \
    PYDOCX_FONT_SIZE, LEGEND_STYLE

from sane_doc_reports.elements import image
from sane_doc_reports.styles.colors import get_colors
from sane_doc_reports.utils import remove_plot_borders, set_legend_style, \
    get_chart_font, set_axis_font, change_legend_vertical_alignment


class BarChartElement(Element):
    style = {
        'title': {
            PYDOCX_FONT_NAME: get_chart_font(),
            PYDOCX_FONT_COLOR: DEFAULT_FONT_COLOR,
            PYDOCX_FONT_SIZE: DEFAULT_TITLE_FONT_SIZE
        }
    }

    @utils.plot
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
        x_axis = None

        if any([True for i in data if 'groups' in i and i['groups']]):
            # Note for future maintainer, I really really... hate stacked
            # bar charts, it made this file look like hell. I hope you cope
            # with matplotlib's shitt* implementation.
            # May the force be with you :pray:

            # Create the stacks
            agg = []
            y_axis = [i['name'] for i in data]
            max_labels_stacked = []
            for v in data:
                names = [i['name'] for i in v['groups']]
                max_labels_stacked = list(set(max_labels_stacked) | set(names))

            labels = sorted(max_labels_stacked)
            colors = get_colors(self.section.layout, labels)

            for v in data:
                current_labels = {i['name']: i['data'][0] for i in v['groups']}
                cols = []
                for l in labels:
                    if l in current_labels:
                        cols.append(current_labels[l])
                    else:
                        cols.append(0)
                agg.append(cols)

            stacked = [i for i in zip(*agg)]

            # Draw each stack
            rects = [plt.barh(y_axis, stacked[0], DEFAULT_BAR_WIDTH, color=colors.pop(0))]

            for i in range(1, len(stacked)):
                left_padding = [sum(i) for i in zip(*stacked[:i])]
                rects.append(plt.barh(y_axis, stacked[i], DEFAULT_BAR_WIDTH,
                                      left=left_padding, color=colors.pop(0)))

            ax = plt.gca()
            legend_location = 'upper center'
            legend_location_relative_to_graph = (0.5, -0.35)
            a = ax.legend(rects, labels, loc=legend_location,
                          bbox_to_anchor=legend_location_relative_to_graph,
                          handlelength=0.7)

        else:
            objects = [i['name'] for i in data]
            colors = get_colors(self.section.layout, objects)

            y_axis = [i for i in range(len(objects))]
            x_axis = [i['data'][0] for i in data]

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
            legend_location = 'upper center'
            legend_location_relative_to_graph = (0.5, -0.35)

            a = ax.legend(rects, fixed_legends, loc=legend_location,
                          bbox_to_anchor=legend_location_relative_to_graph,
                          handlelength=0.7)

            ax.set_yticklabels([])

        # Style the axis and labels
        self.section = change_legend_vertical_alignment(self.section, top=1)
        set_legend_style(a, self.section.layout[LEGEND_STYLE])

        # Fix the axises
        set_axis_font(ax)
        ax.set_yticks(y_axis)
        ax.set_xlabel('')
        ax.invert_yaxis()  # labels read top-to-bottom

        # Fix the xaxis ratio to fit biggest element
        if x_axis:
            ax.set_xlim(0, max(x_axis) + X_AXIS_PADDING)

        # Remove the bottom labels
        remove_plot_borders(ax)
        plt.tick_params(bottom='off')
        plt.title(self.section.extra['title'], **self.style['title'])

        plt_b64 = utils.plt_t0_b64(plt)

        s = Section('image', plt_b64, {}, {'should_shrink': True})
        image.invoke(self.cell_object, s)


def invoke(cell_object, section):
    if section.type != 'bar_chart':
        err_msg = f'Called bar_chart but not bar_chart -  [{section}]'
        return utils.insert_error(cell_object, err_msg)

    BarChartElement(cell_object, section).insert()
