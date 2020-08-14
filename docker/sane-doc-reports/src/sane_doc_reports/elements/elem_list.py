from sane_doc_reports import utils
from sane_doc_reports.domain import CellObject, Section
from sane_doc_reports.domain.Wrapper import Wrapper
from sane_doc_reports.transform.utils import transform_section
from sane_doc_reports.utils import insert_by_type


class ElemListWrapper(Wrapper):
    """ Mainly used to fix the old json's globalSection """

    def wrap(self, invoked_from_wrapper=False):
        # Handle called from another wrapper.
        # if isinstance(self.section.contents, list):
        section_list = self.section.contents

        if section_list == "":
            return

        if not isinstance(section_list, list):
            raise ValueError('Elem list does not have valid contents ' +
                             '(must be a list)')

        for section in section_list:
            section = transform_section(section)

            # Apply the elem list's style as a base style
            section.add_style(self.section.get_style())

            self.cell_object.add_paragraph()
            insert_by_type(section.type, self.cell_object, section)


def invoke(cell_object: CellObject, section: Section,
           invoked_from_wrapper=False):
    if section.type != 'elem_list':
        err_msg = f'Called elem_list but not elem_list -  [{section}]'
        return utils.insert_error(cell_object, err_msg)

    ElemListWrapper(cell_object, section).wrap(
        invoked_from_wrapper=invoked_from_wrapper)
