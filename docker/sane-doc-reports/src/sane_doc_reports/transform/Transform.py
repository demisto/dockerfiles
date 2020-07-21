import json
from typing import List

from sane_doc_reports.conf import LAYOUT_KEY, \
    HEIGHT_POSITION_KEY, WIDTH_POSITION_KEY
from sane_doc_reports.domain.SaneJson import SaneJson
from sane_doc_reports.domain.Page import Page
from sane_doc_reports.transform.utils import transform_old_json_format, \
    general_json_fixes, remove_first_logos


class Transform:
    """ Transforming the sane json into sections per page """

    def __init__(self, sane_json_path: str):
        with open(sane_json_path, 'r') as f:
            self.json_data = json.load(f)

        # Remove the logos
        self.json_data = remove_first_logos(self.json_data)

        # Transform the json if it is an old json's json
        if self.is_old_json_format():
            self.json_data = transform_old_json_format(self.json_data)

        self.json_data = general_json_fixes(self.json_data)
        self.sane_json = SaneJson(self.json_data)

    def get_pages(self) -> List[Page]:
        """
        Get pages and their corresponding section/wrapper objects.
        """
        pages = []

        for _, sane_page in enumerate(self.sane_json.get_sane_pages()):
            page = Page(sane_page)
            page.transform()
            pages.append(page)

        return pages

    def get_sane_json(self):
        """ Return the transformed sane json """
        return self.sane_json

    def is_old_json_format(self):
        json_data = self.json_data

        # Pass through to the json validation in SaneJson
        if len(json_data) == 0 or not isinstance(json_data, list):
            return False

        # Check basic validity of json, will validate in SaneJson
        if any([LAYOUT_KEY not in i for i in json_data]):
            return False

        has_w = WIDTH_POSITION_KEY in json_data[0][LAYOUT_KEY]
        has_h = HEIGHT_POSITION_KEY in json_data[0][LAYOUT_KEY]
        return not has_w or not has_h
