from __future__ import annotations  # Used to fix the __init__ of same type

import json
from typing import Union

from sane_doc_reports.conf import LAYOUT_KEY, DATA_KEY, STYLE_KEY


class Section(object):
    """
    Object that contains element / set of elements.
     Mainly used to enforce the same structure to all sane json's
     elements.
    """

    def __init__(self, type, contents: Union[Section, str, list], layout, extra,
                 attrs={}):
        self.type = type

        # Text contents / or could have children
        # (markdown has children still as str)
        self.contents = contents

        # All of the layout properties, like font/alignment/colors etc...
        self.layout = layout

        # Extra relevant information usually title
        self.extra = extra

        self.attrs = attrs

    def set_style(self, style: dict):
        self.layout[STYLE_KEY] = style

    def add_style(self, added_style: dict, is_new=True):
        if is_new:
            self.set_style({**self.get_style(), **added_style})
        else:
            self.set_style({**added_style, **self.get_style()})

    def get_style(self) -> dict:
        if STYLE_KEY in self.layout:
            return self.layout[STYLE_KEY]
        return {}

    def __str__(self):
        self_dict = {
            'type': self.type,
            'contents': self.contents,
            'layout': self.layout,
            'extra': self.extra
        }
        return json.dumps(self_dict, indent=2)


def sane_to_section(json):
    """
    Gets a Sane json dict as an array and transforms into a Section object
    """

    type = json['type']
    contents = json[DATA_KEY]
    if type in ['markdown', 'text', 'header']:
        contents = json[DATA_KEY]['text']

    layout = json[LAYOUT_KEY]
    extra = {}

    # Insert extra data relevant to the section
    if 'title' in json:
        extra['title'] = json['title']

    return Section(type, contents, layout, extra)
