import struct

from docx.shared import Pt
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

        image = open_b64_image(self.section.contents)

        # Some dark magic here to determine the image width (png)
        w_px, _ = struct.unpack(">LL", image.read(26)[16:24])
        width_pt = int(w_px) * 72 / 96

        should_shrink = self.section.extra.get('should_shrink', False)
        should_resize, size_pt = self.cell_object.get_cell_width_resize(
            width_pt, should_shrink)

        if should_resize:
            self.cell_object.run.add_picture(image, width=Pt(size_pt))
        else:
            self.cell_object.run.add_picture(image)


def invoke(cell_object, section):
    if section.type != 'image':
        section.contents = f'Called image but not image -  [{section}]'
        return error.invoke(cell_object, section)

    has_run(cell_object)

    ImageElement(cell_object, section).insert()
