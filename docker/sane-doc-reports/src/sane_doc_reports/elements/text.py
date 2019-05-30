from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG
from sane_doc_reports.elements import error
from sane_doc_reports.styles.utils import apply_style
from sane_doc_reports.utils import has_run


class TextElement(Element):

    def insert(self):
        if DEBUG:
            print('Adding text...')

        has_run(self.cell_object)
        self.cell_object.run.text = self.section.contents


def invoke(cell_object, section, apply_styling=True) -> None:
    if section.type not in ['header', 'paragraph',
                            'span', 'text', 'p']:
        section.contents = f'Called text but not text -  [{section}]'
        return error.invoke(cell_object, section)

    # Used when called directly from a text element (in the json)
    # So we have to apply the style manually.
    if apply_styling:
        has_run(cell_object)
        apply_style(cell_object, section)

    TextElement(cell_object, section).insert()
