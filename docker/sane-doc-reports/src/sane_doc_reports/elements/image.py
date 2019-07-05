from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG
from sane_doc_reports.elements import error
from sane_doc_reports.utils import open_b64_image, has_run


class ImageElement(Element):

    def insert(self):
        if DEBUG:
            print("Adding image...")

        # Fix empty images
        if self.section.contents == '':
            return

        # TODO: Temp fix for SVG, try to convert it to png somehow (currently
        # blocked because of license)
        if self.section.contents.startswith('data:image/svg+xml'):
            return

        self.cell_object.run.add_picture(
            open_b64_image(self.section.contents))


def invoke(cell_object, section):
    if section.type != 'image':
        section.contents = f'Called image but not image -  [{section}]'
        return error.invoke(cell_object,  section)

    has_run(cell_object)

    ImageElement(cell_object, section).insert()
