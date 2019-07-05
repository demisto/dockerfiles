from typing import List, Union

import mistune
from pyquery import PyQuery

from sane_doc_reports.conf import HTML_NOT_WRAPABLES, DEBUG
from sane_doc_reports.domain.Section import Section


def markdown_to_html(markdown_string: str) -> str:
    """ Convert markdown string to html string """
    if markdown_string is None:
        return '<span> </span>'
    if not isinstance(markdown_string, str):
        raise ValueError('Called markdown_to_html without a markdown string.')
    html = mistune.markdown(markdown_string).strip()
    html = html.replace('\n', '')  # mistune adds unnecessary newlines
    return html


def _wrap(elem):
    """ Wrap an element with a span element """
    span = PyQuery('<span></span>')
    span.html(elem)
    return span


def get_html(children: List) -> str:
    """ Return the concatenated HTML string of a list of PyQuery elements """
    ret = ""
    for child in children:
        if isinstance(child, str):
            ret += child
        else:
            ret += child.outer_html()

    return ret


def check_should_not_wrap(tag, children):
    return tag in HTML_NOT_WRAPABLES and len(children) == 1


def fix_unwrapped_text(root_elem):
    tag = root_elem[0].tag
    children = root_elem.contents()
    should_not_wrap = check_should_not_wrap(tag, children)
    fixed_children = _fix_unwrapped_text(children, do_not_wrap=should_not_wrap)
    fixed_element = PyQuery(f'<{tag}></{tag}>')
    fixed_element.html(get_html(fixed_children))
    return fixed_element


def _fix_unwrapped_text(children: PyQuery, do_not_wrap=False) -> List[PyQuery]:
    """ Add spans over all elements and their sub elements except other spans"""
    ret = []
    if do_not_wrap and len(children) == 1:
        for i in children:
            if isinstance(i, str):
                ret.append(i)
            else:
                for fixed in fix_unwrapped_text(PyQuery(i)):
                    ret.append(PyQuery(fixed))  # PyQuery(i).outer_html())
        return ret

    if len(children) == 1 and isinstance(children[0], str):
        return [children[0]]

    for child in children:
        if isinstance(child, str) and len(children) > 1:
            ret.append(_wrap(child))
            continue

        tag = child.tag
        attribs = "".join([f'{k}="{v}" ' for k, v in child.attrib.items()])
        child = PyQuery(child)
        descendants = _fix_unwrapped_text(child.contents(),
                                          do_not_wrap=tag in HTML_NOT_WRAPABLES)
        descendants_html = ""
        for i in descendants:
            if isinstance(i, str):
                descendants_html += i
            else:
                descendants_html += i.outer_html()

        if tag in HTML_NOT_WRAPABLES:
            child.html(descendants_html)
            ret.append(child)
        else:
            child = PyQuery(f'<{tag} {attribs}>{descendants_html}</{tag}>')
            ret.append(_wrap(child))

    return ret


def build_dict_from_sane_json(elem: PyQuery, already_wrapped=False) -> dict:
    # Find if has children
    elem = PyQuery(elem)
    children = list(elem.contents())
    has_children = len(elem.children()) > 0

    contents = []
    if has_children:
        # Fix unwrapped children
        if not already_wrapped:
            children = fix_unwrapped_text(elem).contents()

        for child in children:
            child_dict = build_dict_from_sane_json(child, already_wrapped=True)
            if child_dict:
                contents.append(child_dict)
    else:
        contents = elem.html()

    extra = {}

    # Only tables need the HTML (to use later for extraction of relevant data)
    if elem.is_("table"):
        extra = {'original_html': str(elem)}

    if 'src' in elem[0].attrib:
        extra['src'] = elem.attr('src')
    if 'href' in elem[0].attrib:
        extra['href'] = elem.attr('href')

    return {'type': list(elem)[0].tag, 'attrs': [], 'layout': {},
            'contents': contents,
            'extra': extra}


def collapse_attrs(section_list: List[Union[Section, dict]]) -> list:
    """ Collapse all of the sections
    (moving em as attributes or removing redundant elements like <p>) """
    from sane_doc_reports.transform.markdown.MarkdownSection import \
        MarkdownSection
    ret = []
    for section in section_list:
        if isinstance(section, MarkdownSection):
            s = MarkdownSection(section.type, section.contents,
                                section.layout, section.extra, section.attrs)
        else:
            s = MarkdownSection(section['type'], section['contents'],
                                section['layout'], section['extra'],
                                section['attrs'])
        s.collapse(False)
        ret.append(s)
    return ret


def markdown_to_section_list(markdown_string) -> List[Section]:
    """ Convert markdown to HTML->Python list,
        This will be a readable list of dicts containing:
            - Type: type of html element
            - Contents: text content or list of other dicts
            - Attrs (any defined sane_doc_reports.conf.HTML_ATTRIBUTES)

        For example:
        markdown = '**~~123~~**'
        -> <p><strong><strike>123</strike></strong></p>
        ->[
          {
            "type": "p",
            "attrs": ["strong","strike"],
            "contents": "123"
          }
        ]
        -> [Section Object]
    """
    html = markdown_to_html(markdown_string)
    etree_root = PyQuery(html)
    html_list = list(
        map(build_dict_from_sane_json, [c for c in list(etree_root)]))
    collapsed = collapse_attrs(html_list)

    if DEBUG:
        print("markdown_to_section list: ",
              "".join([str(i) for i in collapsed]))

    return collapsed
