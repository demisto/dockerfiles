from sane_doc_reports import utils
from sane_doc_reports.elements.table import TableElement


def invoke(cell_object, section):
    if section.type != 'list':
        err_msg = f'Called list but not list -  [{section}]'
        return utils.insert_error(cell_object, err_msg)

    section.extra['list_style'] = True
    TableElement(cell_object, section).insert()
