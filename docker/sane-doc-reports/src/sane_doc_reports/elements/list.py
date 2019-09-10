from sane_doc_reports.elements import error
from sane_doc_reports.elements.table import TableElement


def invoke(cell_object, section):
    if section.type != 'list':
        section.contents = f'Called list but not list -  [{section}]'
        return error.invoke(cell_object, section)

    section.extra['list_style'] = True
    TableElement(cell_object, section).insert()
