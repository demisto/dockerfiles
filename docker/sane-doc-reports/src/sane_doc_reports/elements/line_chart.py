import matplotlib.pyplot as plt
from matplotlib.pyplot import figure

from sane_doc_reports import utils
from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG, PYDOCX_FONT_NAME, \
    DEFAULT_FONT_COLOR, DEFAULT_TITLE_FONT_SIZE, \
    PYDOCX_FONT_COLOR, PYDOCX_FONT_SIZE, LEGEND_STYLE, MAX_AXIS_LABELS
from sane_doc_reports.domain.Section import Section
from sane_doc_reports.elements import image
from sane_doc_reports.styles.colors import get_colors
from sane_doc_reports.utils import remove_plot_borders, \
    set_legend_style, get_chart_font, set_axis_font, \
    change_legend_vertical_alignment, set_legend_max_count


def fix_data(data):
    dates = [i['name'] for i in data]
    new_groups = {}

    last_name = 'value'
    for group in data:
        if group.get('groups', None) is None:
            data_val = group.get('data', [0])[0]
            group['groups'] = [{'name': last_name, "data": [data_val]}]

        for line in group.get('groups', []):
            if line['name'] not in new_groups:
                last_name = line['name']
                new_groups[line['name']] = {
                    'dates': dates,
                    'values': [0] * len(dates)
                }

    # Populate the data
    for index, group in enumerate(data):
        for line in group.get('groups', []):
            if line['name'] in new_groups:
                new_groups[line['name']]['values'][index] += line['data'][0]

    return new_groups


class LineChartElement(Element):
    style = {
        'title': {
            PYDOCX_FONT_NAME: get_chart_font(),
            PYDOCX_FONT_COLOR: DEFAULT_FONT_COLOR,
            PYDOCX_FONT_SIZE: DEFAULT_TITLE_FONT_SIZE
        }
    }

    @utils.plot
    def insert(self):
        if DEBUG:
            print("Adding line chart...")

            # Fix sizing
        size_w, size_h, dpi = utils.convert_plt_size(self.section,
                                                     self.cell_object)
        figure(num=2, figsize=(size_w, size_h), dpi=dpi,
               constrained_layout=False)

        data = self.section.contents

        fix_data(data)

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
        groups = fix_data(data)

        # Fix empty key
        if '' in groups.keys():
            groups['None'] = groups.pop('')

        # Generate the default colors
        colors = get_colors(self.section.layout, groups.keys())
        unassigned_color = 'darkgrey'

        # If we have predefined colors, use them
        if 'legend' in self.section.layout and self.section.layout['legend']:
            for i in self.section.layout['legend']:
                if 'color' in i:
                    colors.append(i['color'])
                elif 'fill' in i:
                    colors.append(i['fill'])

        color_keys = {}
        for i, k in enumerate(groups.keys()):
            color_keys[k] = colors[i]
            if k == 'Unassigned':
                color_keys['Unassigned'] = unassigned_color

        final_colors = {k: color_keys[k] for k in groups.keys()}

        # Plot the lines
        for group, line in groups.items():
            x_axis = line['dates']
            y_axis = line['values']
            plt.plot(x_axis, y_axis, marker='', color=final_colors[group],
                     linewidth=2)

        # Create and move the legend outside
        ax = plt.gca()

        # Auto rotate the labels
        remove_plot_borders(ax)
        legend_location = 'upper center'
        legend_location_relative_to_graph = (0.5, -0.35)

        handles = [plt.Rectangle((0, 0), 1, 1, fc=final_colors[i]) for i in
                   groups.keys()]

        legend = ax.legend(handles, [i for i in groups.keys()],
                           loc=legend_location,
                           bbox_to_anchor=legend_location_relative_to_graph,
                           handlelength=0.7, handleheight=0.7, ncol=2)

        self.section = change_legend_vertical_alignment(self.section, top=1)

        # Set max ticks in xaxis to be MAX_AXIS_LABELS
        set_legend_max_count(ax, self.cell_object)

        set_legend_style(legend, self.section.layout[LEGEND_STYLE])
        set_axis_font(ax)
        ax.set_title(self.section.extra['title'], **self.style['title'])

        # Add to docx as image
        plt_b64 = utils.plt_t0_b64(plt, (size_w, size_h), dpi)
        s = Section('image', plt_b64, {}, {'should_shrink': True})
        image.invoke(self.cell_object, s)


def invoke(cell_object, section):
    if section.type != 'line_chart':
        err_msg = f'Called line_chart but not line_chart - [{section}]'
        return utils.insert_error(cell_object, err_msg)

    LineChartElement(cell_object, section).insert()
