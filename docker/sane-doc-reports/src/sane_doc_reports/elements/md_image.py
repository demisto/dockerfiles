import base64

import requests

from sane_doc_reports.domain.Element import Element
from sane_doc_reports.domain.Section import Section
from sane_doc_reports.conf import DEBUG, MD_TYPE_IMAGE
from sane_doc_reports.elements import image, error


def image_contents_from_url(url):
    requests.packages.urllib3.disable_warnings()

    r = requests.get(url, verify=False)
    return "data:" + \
           r.headers['Content-Type'] + ";" + \
           "base64," + str(base64.b64encode(r.content).decode("utf-8"))


class ExternalImageElement(Element):

    def insert(self):
        if DEBUG:
            print('Adding md (external) image...')

        url = self.section.extra['src']
        image_data = image_contents_from_url(url)
        img_section = Section('image', image_data, {}, {})
        image.invoke(self.cell_object, img_section)


def invoke(cell_object, section) -> None:
    if section.type != MD_TYPE_IMAGE:
        section.contents = f'Called image but not image -  [{section}]'
        return error.invoke(cell_object, section)

    ExternalImageElement(cell_object, section).insert()
