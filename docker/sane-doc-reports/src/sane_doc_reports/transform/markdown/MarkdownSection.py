import json
from typing import Union, List

from sane_doc_reports.conf import HTML_ATTRIBUTES, HTML_ATTR_MARKDOWN_MAP, \
    HTML_REDUNDANT_COLLAPSIBLE

from sane_doc_reports.domain.Section import Section
import sane_doc_reports.transform.markdown.md_helpers as md


def _should_collapse(has_siblings, section_type):
    return not has_siblings and section_type in HTML_ATTRIBUTES \
           or section_type in HTML_REDUNDANT_COLLAPSIBLE


class MarkdownSection(Section):
    """
     Extension of Section that provides collapsing of
     redundant attributes and children elements (coming form
     md to html conversions)
    """

    def __init__(self, type, contents: Union[List[Section], str],
                 layout, extra, attrs=[]):

        super().__init__(type, contents, layout, extra)
        self.type = type
        self.attrs = attrs

        if isinstance(contents, list):
            self.contents = md.collapse_attrs(contents)
        else:
            self.contents = contents

        self.extra = extra

    def collapse(self, has_siblings) -> bool:
        """ Recursively collapse the HTML style elements into attributes """

        # If we got to the end return if we should collapse
        if self.is_leaf():
            return _should_collapse(has_siblings, self.type)

        # This is the only time when we can collapse
        if self.has_child():
            child = self.get_child()
            collapsible = child.collapse(False)
            if collapsible:
                self.collapse_child()

            new_child = self.get_child()
            if new_child:
                parent_collapsible = _should_collapse(has_siblings, new_child.type)
                if parent_collapsible:
                    self.collapse_child()

            return _should_collapse(has_siblings, self.type)

        # Recursively go through all the section.
        if self.has_children():
            for child in self.contents:
                collapsible = child.collapse(True)
                if collapsible:
                    child.collapse_child()
                else:
                    child.swap_attr()
        return False

    def add_attr(self, attrs):
        new_attributes = set(self.attrs)
        for attr in attrs:
            mapped_attr = attr
            if attr in HTML_ATTR_MARKDOWN_MAP:
                mapped_attr = HTML_ATTR_MARKDOWN_MAP[attr]
            new_attributes.add(mapped_attr)
        self.attrs = sorted(list(new_attributes))

    def collapse_child(self):
        """ Collapse the child element and move it as an attribute to self """
        if self.has_child():
            child = self.contents[0]
            attr_type = [child.type] if child.type in HTML_ATTRIBUTES else []
            self.add_attr(child.attrs + attr_type)
            self.contents = child.contents

    def swap_attr(self):
        """ Swap element type to be textual and move type to be an attr """
        if self.type in HTML_ATTRIBUTES:
            t = self.type
            self.type = 'p'
            self.add_attr([t])

    def has_children(self):
        return isinstance(self.contents, list) and len(self.contents) > 1

    def has_child(self):
        return isinstance(self.contents, list) and len(self.contents) == 1

    def get_child(self):
        if isinstance(self.contents, list):
            return self.contents[0]

    def is_leaf(self):
        return isinstance(self.contents, str)

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True, indent=2)

    def get_dict(self):
        return json.loads(self.to_json())

    def get_extra(self, key, provided=False):
        if key not in self.extra:
            return provided
        return self.extra[key]

    def propagate_extra(self, key, value, only_multiple_children=True):
        """ propagate an extra down to all children
            only_multiple_children - mainly used to propagate "inline" extra,
            in a way that we only want to inline elements that have siblings
             (so we don't propagate when this element doesn't have multiple
              children).
        """
        self.extra[key] = value

        if not isinstance(self.contents, list):
            return

        if only_multiple_children and not self.has_children():
            return

        for child in self.contents:
            child.propagate_extra(key, value)

    def __str__(self):
        return self.to_json()
