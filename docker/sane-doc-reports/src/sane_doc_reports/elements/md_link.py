import docx
from docx.enum.dml import MSO_THEME_COLOR_INDEX

from sane_doc_reports import utils
from sane_doc_reports.domain.Element import Element
from sane_doc_reports.conf import DEBUG
from sane_doc_reports.populate.utils import insert_text


def add_hyperlink_into_run(paragraph, run, url):
    runs = paragraph.runs
    i = 0
    for i in range(len(runs)):
        if runs[i].text == run.text:
            break

    # This gets access to the document.xml.rels file and gets a new
    #  relation id value
    part = paragraph.part
    r_id = part.relate_to(url, docx.opc.constants.RELATIONSHIP_TYPE.HYPERLINK,
                          is_external=True)

    # Create the w:hyperlink tag and add needed values
    hyperlink = docx.oxml.shared.OxmlElement('w:hyperlink')
    hyperlink.set(docx.oxml.shared.qn('r:id'), r_id, )
    hyperlink.append(run._r)
    paragraph._p.insert(i + 1, hyperlink)

    # Add the style
    if run.font.color.rgb is None:
        run.font.color.theme_color = MSO_THEME_COLOR_INDEX.HYPERLINK

    run.font.underline = True


class LinkElement(Element):

    def insert(self):
        if DEBUG:
            print('Adding link...')

        insert_text(self.cell_object, self.section.contents)

        add_hyperlink_into_run(self.cell_object.paragraph, self.cell_object.run,
                               self.section.extra['href'])


def invoke(cell_object, section) -> None:
    if section.type not in ['a']:
        err_msg = f'Called link but not link -  [{section}]'
        return utils.insert_error(cell_object, err_msg)

    LinkElement(cell_object, section).insert()
