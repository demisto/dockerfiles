from sane_doc_reports.domain import SaneJsonPage
from sane_doc_reports.transform.utils import transform_section


class Page:
    """ Contains Sections relevant for the page"""

    def __init__(self, sane_page: SaneJsonPage):
        self._sane_page = sane_page
        self.sections = []

    def transform(self):
        for sane_section in self._sane_page.get_sections():
            section = transform_section(sane_section)
            self.sections.append(section)

    def __iter__(self):
        return iter(self.sections)
