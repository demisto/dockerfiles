import matplotlib.pyplot as plt
from matplotlib.pyplot import figure

from sane_doc_reports import utils
from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG, DEFAULT_ALPHA
from sane_doc_reports.domain.Section import Section
from sane_doc_reports.elements import error, image
from sane_doc_reports.utils import get_ax_location, remove_plot_borders, \
    set_legend_style


class LineChartElement(Element):

    def insert(self):
        if DEBUG:
            print("Adding line chart...")

            # Fix sizing
        size_w, size_h, dpi = utils.convert_plt_size(self.section)
        figure(num=2, figsize=(size_w, size_h), dpi=dpi)

        data = self.section.contents

        # Make the groups look like:
        # groups = {
        #   'Type A': {
        #       dates: ['2000', '2001', '2002']
        #       values: ['1', '2', '3']
        #    }
        #   'Type B': {
        #         dates: ['2000', '2001', '2002'],
        #         values : ['4', '5', '6']
        # }
        groups = {}
        for date_group in data:
            for line in date_group['groups']:
                if line['name'] not in groups:
                    groups[line['name']] = {
                        'dates': [date_group['name']],
                        'values': [line['data'][0]]
                    }
                    continue
                groups[line['name']]['dates'].append(date_group['name'])
                groups[line['name']]['values'].append(line['data'][0])

        legend_colors = {i['name']: i['color'] for i in
                         self.section.layout['legend']}

        # Plot the lines
        for group, line in groups.items():
            x_axis = line['dates']
            y_axis = line['values']
            plt.plot(x_axis, y_axis, marker='', color=legend_colors[group],
                     linewidth=2)

        # Create and move the legend outside
        ax = plt.gca()
        remove_plot_borders(ax)
        legend_location = 'upper center'
        legend_location_relative_to_graph = (0.5, -0.35)

        a = ax.legend([i for i in groups.keys()], loc=legend_location,
                      bbox_to_anchor=legend_location_relative_to_graph)

        set_legend_style(a)
        a.get_frame().set_alpha(DEFAULT_ALPHA)
        a.get_frame().set_linewidth(0.0)


        # Add to docx as image
        plt_b64 = utils.plt_t0_b64(plt)
        s = Section('image', plt_b64, {}, {})
        image.invoke(self.cell_object, s)


def invoke(cell_object, section):
    if section.type != 'line_chart':
        section.contents = f'Called line_chart but not line_chart - [{section}]'
        return error.invoke(cell_object, section)

    LineChartElement(cell_object, section).insert()
