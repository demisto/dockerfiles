from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG
from sane_doc_reports.elements import error


class LineChartElement(Element):

    def insert(self):
        if DEBUG:
            print("Adding line chart...")


def invoke(cell_object, section):
    if section.type != 'line_chart':
        section.contents = f'Called line_chart but not line_chart - [{section}]'
        return error.invoke(cell_object, section)

    LineChartElement(cell_object, section).insert()
