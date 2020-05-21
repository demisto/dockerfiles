import struct

from docx.shared import Inches

from sane_doc_reports import utils
from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG, DEFAULT_DPI, MD_TYPE_IMAGE
from sane_doc_reports.elements import md_image
from sane_doc_reports.utils import open_b64_image, has_run, fix_svg_to_png


def pixels_to_inches(pixels) -> int:
    return pixels * (1 / DEFAULT_DPI)


class ImageElement(Element):

    def insert(self):
        if DEBUG:
            print("Adding image...")

        # Fix empty images
        if self.section.contents == '':
            return

        if self.section.contents.startswith('http://') or \
           self.section.contents.startswith('https://'):
            self.section.type = MD_TYPE_IMAGE
            self.section.extra['src'] = self.section.contents
            md_image.invoke(self.cell_object, self.section)
            return

        image = None
        should_shrink = False
        if self.section.contents.startswith('data:image/svg+xml;base64'):
            image = fix_svg_to_png(self.section.contents)
        else:
            image = open_b64_image(self.section.contents)

            # Some dark magic here to determine the image width (png)
            w_px, h_px = struct.unpack(">LL", image.read(26)[16:24])
            width_inch = pixels_to_inches(int(w_px))
            height_inch = pixels_to_inches(int(h_px))

            should_shrink = self.section.extra.get('should_shrink', False)

        if should_shrink:
            width_inch *= 0.91  # (the size that was calculated was without-
            # regards to margins in the doc, let's remove them here)
            self.cell_object.run.add_picture(image, width=Inches(width_inch),
                                             height=Inches(height_inch))
        else:
            self.cell_object.run.add_picture(image)


def invoke(cell_object, section):
    if section.type != 'image':
        err_msg = f'Called image but not image -  [{section}]'
        return utils.insert_error(cell_object, err_msg)

    has_run(cell_object)

    ImageElement(cell_object, section).insert()
