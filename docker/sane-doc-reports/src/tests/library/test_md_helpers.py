from sane_doc_reports.conf import MD_TYPE_QUOTE
from sane_doc_reports.transform.markdown.MarkdownSection import MarkdownSection
from sane_doc_reports.transform.markdown.md_helpers import *
from sane_doc_reports.transform.markdown.md_helpers import \
    build_dict_from_sane_json


def test_markdown_to_html_none():
    md_input = None
    ex_output = MD_EMPTY
    assert markdown_to_html(md_input) == ex_output


def test_markdown_to_html_empty_string():
    md_input = ' '
    ex_output = MD_EMPTY
    assert markdown_to_html(md_input) == ex_output


def test_markdown_to_html_multiple_empty_string():
    md_input = '   '
    ex_output = MD_EMPTY
    assert markdown_to_html(md_input) == ex_output


def test_markdown_to_html_default():
    md_input = 'test'
    ex_output = '<p>test</p>'
    assert markdown_to_html(md_input) == ex_output


def test_markdown_to_html_header():
    md_input = '### test'
    ex_output = '<h3>test</h3>'
    assert markdown_to_html(md_input) == ex_output


def test_markdown_to_html_paragraph():
    md_input = 'test\n\ntest'
    ex_output = '<p>test</p><p>test</p>'
    assert markdown_to_html(md_input) == ex_output


def test_markdown_to_html_link():
    md_input = '[text](url)'
    ex_output = '<p><a href="url">text</a></p>'
    assert markdown_to_html(md_input) == ex_output


def test_markdown_to_html_code():
    md_input = 'test'
    ex_output = '<p>test</p>'
    assert markdown_to_html(md_input) == ex_output


def test_markdown_to_html_quote():
    md_input = '> test'
    ex_output = '<blockquote><p>test</p></blockquote>'
    assert markdown_to_html(md_input) == ex_output


def test_markdown_to_html_hr():
    md_input = '\n---\n'
    ex_output = '<hr>'
    assert markdown_to_html(md_input) == ex_output


def test_markdown_to_html_ul():
    md_input = '1. test'
    ex_output = '<ol><li>test</li></ol>'
    assert markdown_to_html(md_input) == ex_output


def test_markdown_to_html_ol():
    md_input = '- test\n* test2'
    ex_output = '<ul><li>test</li><li>test2</li></ul>'
    assert markdown_to_html(md_input) == ex_output

    md_input = '- test\n* test2\n\t- test3'
    ex_output = '<ul><li>test</li><li>test2<ul><li>test3</li>' + \
                '</ul></li></ul>'
    assert markdown_to_html(md_input) == ex_output


def test_markdown_to_html_text_styles():
    md_input = '**test**'
    ex_output = '<p><strong>test</strong></p>'
    assert markdown_to_html(md_input) == ex_output

    md_input = '~~test~~'
    ex_output = '<p><del>test</del></p>'
    assert markdown_to_html(md_input) == ex_output

    md_input = '*test*'
    ex_output = '<p><em>test</em></p>'
    assert markdown_to_html(md_input) == ex_output

    md_input = '- *test*'
    ex_output = '<ul><li><em>test</em></li></ul>'
    assert markdown_to_html(md_input) == ex_output


def test_markdown_to_html_md_button():
    md_input = '%%%{"message":"hi 1", "action":"Print", "params": {"value": "we are the best"}}%%%'
    ex_output = '<p><p>hi 1</p></p>'
    assert markdown_to_html(md_input) == ex_output

    inner = '{\'message":"hi 1", "action":"Print", "params": {"value": "we are the best"}}'
    md_input = f'%%%{inner}%%%'
    ex_output = f'<p><p>{inner}</p></p>'
    assert markdown_to_html(md_input) == ex_output

    inner = '123123'
    md_input = f'%%%{inner}%%%'
    ex_output = f'<p><p>{inner}</p></p>'
    assert markdown_to_html(md_input) == ex_output


def test_fix_unwrapped_no_tags():
    html = 'test'
    root_elem = PyQuery(html)
    res = fix_unwrapped_text(root_elem)
    res_check = res.outer_html()
    expected = PyQuery('<p>test</p>')
    assert res_check == expected.outer_html()


def test_fix_unwrapped_em_tag():
    html = '<em>wrapped</em>'
    root_elem = PyQuery(html)
    res = fix_unwrapped_text(root_elem)
    res_check = res.outer_html()
    expected = PyQuery('<em>wrapped</em>')
    assert res_check == expected.outer_html()


def test_fix_unwrapped_text_basic():
    html = '<p>1<b>2</b>3</p>'
    root_elem = PyQuery(html)
    res = fix_unwrapped_text(root_elem)
    res_check = res.outer_html()
    expected = PyQuery(
        '<p><span>1</span><span><b>2</b></span><span>3</span></p>')
    assert res_check == expected.outer_html()


def test_fix_unwrapped_text_basic_2():
    html = '<p><b>2</b>3</p>'
    root_elem = PyQuery(html)
    res = fix_unwrapped_text(root_elem)
    res_check = res.outer_html()
    expected = PyQuery('<p><span><b>2</b></span><span>3</span></p>')
    assert res_check == expected.outer_html()


def test_fix_unwrapped_text_basic_3():
    html = '<p><strong>test</strong> unwrapped</p>'
    root_elem = PyQuery(html)
    res = fix_unwrapped_text(root_elem)
    res_check = res.outer_html()
    expected = PyQuery('<p><span><strong>test</strong></span><span> unwrapped' +
                       '</span<</p>')
    assert res_check == expected.outer_html()


def test_fix_unwrapped_text_basic_4():
    html = '<p><i>a</i><b>b</b><c>c</c></p>'
    root_elem = PyQuery(html)
    res = fix_unwrapped_text(root_elem)
    res_check = res.outer_html()
    expected = PyQuery(
        '<p><span><i>a</i></span><span><b>b</b></span><span><c>c' +
        '</c></span></p>')
    assert res_check == expected.outer_html()


def test_fix_unwrapped_text_deep():
    html = '<span><strong>12<b>3</b></strong></span>'
    root_elem = PyQuery(html)

    res = fix_unwrapped_text(root_elem)
    res_check = res.outer_html()
    expected = PyQuery('<p><span><strong><span>12</span><span><b>3</b></span>' +
                       '</strong></span></p>')
    assert res_check == expected.html()


def test_fix_unwrapped_text_attributes():
    html = '<p><strong attr="123">test</strong> unwrapped</p>'
    root_elem = PyQuery(html)

    res = fix_unwrapped_text(root_elem)
    res_check = res.outer_html()
    expected = PyQuery('<p><span><strong attr="123">test</strong></span>' +
                       '<span> unwrapped</span></p>')
    assert res_check == expected.outer_html()


def test_fix_unwrapped_no_unwrapped_basic():
    html = '<span>wrapped</span>'
    root_elem = PyQuery(html)
    res = fix_unwrapped_text(root_elem)
    res_check = res.outer_html()
    expected = PyQuery('<span>wrapped</span>')
    assert res_check == expected.outer_html()


def test_fix_unwrapped_text_no_unwrapped_basic():
    html = '<span><strong>123</strong></span>'
    root_elem = PyQuery(html)
    res = fix_unwrapped_text(root_elem)
    res_check = res.outer_html()
    expected = PyQuery('<p><span><strong>123</strong></span></p>')
    assert res_check == expected.html()


def test_fix_unwrapped_text_no_unwrapped_basic_2():
    html = '<p><span>123</span></p>'
    root_elem = PyQuery(html)
    res = fix_unwrapped_text(root_elem)
    res_check = res.outer_html()
    expected = PyQuery('<p><span>123</span></p>')
    assert res_check == expected.outer_html()


def test_fix_unwrapped_text_no_unwrapped_complex():
    html = '<p><span><i>a</i></span><span><b>b</b></span></p>'
    root_elem = PyQuery(html)
    res = fix_unwrapped_text(root_elem)
    res_check = res.outer_html()
    expected = PyQuery('<p><span><i>a</i></span><span><b>b</b></span></p>')
    assert res_check == expected.outer_html()


def test_fix_unwrapped_text_ul_basic():
    html = '<ul><li>123</li></ul>'
    root_elem = PyQuery(html)
    res = fix_unwrapped_text(root_elem)
    res_check = res.outer_html()
    expected = PyQuery('<ul><li>123</li></ul>')
    assert res_check == expected.outer_html()


def test_build_dict_ol_with_nesting():
    markdown_string = '1. parent\n2. child\n\t1. nested'
    html = markdown_to_html(markdown_string).strip()
    root_elem = PyQuery(html)
    res = fix_unwrapped_text(root_elem)
    res_check = res.outer_html()
    expected = PyQuery(
        '<ol><li>parent</li><li><span>child</span><ol><li>nested</li>' +
        '</ol></li></ol>')
    assert res_check == expected.outer_html()


def test_fix_unwrapped_text_complex():
    html = '<p>aaa <em>bbb <i>ccc</i></em> ddd <del>eee</del> fff</p>'
    root_elem = PyQuery(html)
    res = fix_unwrapped_text(root_elem)
    res_check = res.outer_html()
    expected = PyQuery('<p><span>aaa </span><span><em><span>bbb </span><span>' +
                       '<i>ccc</i></span></em></span><span> ddd </span><span>' +
                       '<del>eee</del></span><span> fff</span></p>')
    assert res_check == expected.outer_html()


def test_fix_unwrapped_text_complex_2():
    html = '<p>aaa <em>bbb <i>ccc<q>zzz</q>ddd</i></em> ddd <del>' + \
           'eee</del> fff</p>'
    root_elem = PyQuery(html)
    res = fix_unwrapped_text(root_elem)
    res_check = res.outer_html()
    expected = PyQuery('<p><span>aaa </span><span><em><span>bbb </span><span>' +
                       '<i><span>ccc</span><span><q>zzz</q></span><span>ddd' +
                       '</span></i></span></em></span><span> ddd </span>' +
                       '<span><del>eee</del></span><span> fff</span></p>')
    assert res_check == expected.outer_html()


def test_fix_unwrapped_text_complex_3():
    html = '<p>aaa <em>bbb <i>ccc<span><p>zzz</p></span>ddd</i>' + \
           '</em> ddd <del>eee</del> fff</p>'
    root_elem = PyQuery(html)
    res = fix_unwrapped_text(root_elem)
    res_check = res.outer_html()
    expected = PyQuery('<p><span>aaa </span><span><em><span>bbb </span><span>' +
                       '<i><span>ccc</span><span><p>zzz</p></span><span>ddd' +
                       '</span></i></span></em></span><span> ddd </span>' +
                       '<span><del>eee</del></span><span> fff</span></p>')
    assert res_check == expected.outer_html()


def test_no_change_fix_unwrapped_text_complex():
    html = '<p><span>aaa </span><span><em><span>bbb </span><span>' + \
           '<i><span>ccc</span><span><p>zzz</p></span><span>ddd' + \
           '</span></i></span></em></span><span> ddd </span><span>' + \
           '<del>eee</del></span><span> fff</span></p>'
    root_elem = PyQuery(html)
    res = fix_unwrapped_text(root_elem)
    res_check = res.outer_html()
    expected = PyQuery('<p><span>aaa </span><span><em><span>bbb </span><span>' +
                       '<i><span>ccc</span><span><p>zzz</p></span><span>ddd' +
                       '</span></i></span></em></span><span> ddd </span>' +
                       '<span><del>eee</del></span><span> fff</span></p>')
    assert res_check == expected.outer_html()


def test_collapse_attrs_basic():
    input_dict = [{"type": "span", "attrs": [], "layout": {}, "extra": {},
                   "contents": [
                       {"type": "strong", "attrs": [], "layout": {},
                        "extra": {},
                        "contents": "test"}
                   ]}]

    res = collapse_attrs(input_dict)
    expected = [MarkdownSection("span", "test", {}, {}, ["bold"])]
    assert res[0].get_dict() == expected[0].get_dict()


def test_collapse_attrs_nested():
    input_dict = [{"type": "span", "attrs": [], "layout": {}, "extra": {},
                   "contents": [
                       {"type": "strong", "attrs": [], "layout": {},
                        "extra": {},
                        "contents": [
                            {"type": "strong", "attrs": [], "layout": {},
                             "extra": {},
                             "contents": "test"}
                        ]}
                   ]}]

    res = collapse_attrs(input_dict)
    expected = [MarkdownSection("span", "test", {}, {}, ["bold"])]
    assert res[0].get_dict() == expected[0].get_dict()


def test_collapse_attrs_multiple_nested():
    input_dict = [{"type": "span", "attrs": [], "layout": {}, "extra": {},
                   "contents": [
                       {"type": "strong", "attrs": [], "layout": {},
                        "extra": {},
                        "contents": [
                            {"type": "em", "attrs": [], "layout": {},
                             "extra": {},
                             "contents": "test"}
                        ]}
                   ]}]

    res = collapse_attrs(input_dict)
    expected = [MarkdownSection("span", "test", {}, {}, ["bold", "italic"])]
    assert res[0].get_dict() == expected[0].get_dict()


def test_collapse_attrs_inner_nesting():
    input_dict = [{"type": "span", "attrs": [], "layout": {}, "extra": {},
                   "contents": [
                       {"type": "strong", "attrs": [], "layout": {},
                        "extra": {},
                        "contents": [
                            {"type": "em", "attrs": [], "layout": {},
                             "extra": {},
                             "contents": [
                                 {"type": "strong", "attrs": [], "layout": {},
                                  "extra": {}, "contents": "test"}]
                             }
                        ]}
                   ]}]

    res = collapse_attrs(input_dict)
    expected = [MarkdownSection("span", "test", {}, {}, ["bold", "italic"])]
    assert res[0].get_dict() == expected[0].get_dict()


def test_collapse_attrs_inner_nesting_deep():
    input_dict = [{"type": "span", "attrs": [], "layout": {}, "extra": {},
                   "contents": [
                       {"type": "strong", "attrs": [], "layout": {},
                        "extra": {},
                        "contents": [
                            {"type": "strong", "attrs": [], "layout": {},
                             "extra": {},
                             "contents": [
                                 {"type": "em", "attrs": [], "layout": {},
                                  "extra": {},
                                  "contents": [
                                      {"type": "strong", "attrs": [],
                                       "layout": {},
                                       "extra": {}, "contents": "test"}]
                                  }
                             ]}
                        ]}
                   ]}]

    res = collapse_attrs(input_dict)
    expected = [MarkdownSection("span", "test", {}, {}, ["bold", "italic"])]
    assert res[0].get_dict() == expected[0].get_dict()


def test_collapse_attrs_not_all_collapsable():
    input_dict = [{"type": "span", "attrs": [], "layout": {}, "extra": {},
                   "contents": [
                       {"type": "strong", "attrs": [], "layout": {},
                        "extra": {},
                        "contents": [
                            {"type": "sometag", "attrs": [], "layout": {},
                             "extra": {},
                             "contents": "test"}
                        ]}
                   ]}]

    res = collapse_attrs(input_dict)
    expected = [MarkdownSection("span", [
        MarkdownSection("sometag", "test", {}, {})
    ], {}, {}, ["bold"])]
    assert res[0].get_dict() == expected[0].get_dict()


def test_build_dict_basic():
    markdown_string = 'some string'  # 'tes *can **also*** be ~~the~~ nested...'
    html = markdown_to_html(markdown_string).strip()
    root_elem = PyQuery(html)
    res = build_dict_from_sane_json(root_elem)
    expected = {'type': 'p', 'contents': 'some string', 'attrs': [],
                'layout': {}, 'extra': {}}
    assert res == expected


def test_build_dict_basic_element():
    markdown_string = 'some **string**'
    html = markdown_to_html(markdown_string).strip()
    root_elem = PyQuery(html)
    res = build_dict_from_sane_json(root_elem)
    expected = {'type': 'p', 'contents': [
        {'type': 'span', 'contents': 'some ', 'attrs': [],
         'layout': {}, 'extra': {}},
        {'type': 'span', 'contents': [
            {'type': 'strong', 'contents': 'string', 'attrs': [],
             'layout': {}, 'extra': {}}
        ], 'attrs': [], 'layout': {}, 'extra': {}}
    ], 'attrs': [], 'layout': {}, 'extra': {}
                }
    assert res == expected


def test_build_dict_md_code():
    markdown_string = '`some string`'
    html = markdown_to_html(markdown_string).strip()
    root_elem = PyQuery(html)
    res = build_dict_from_sane_json(root_elem)
    expected = {'type': 'p', 'attrs': [], 'layout': {}, 'contents': [
        {'type': 'code', 'attrs': [], 'layout': {},
         'contents': 'some string', 'extra': {}}
    ], 'extra': {}}
    assert res == expected


def test_build_dict_deep_ul():
    markdown_string = '- parent\n\t- child'
    html = markdown_to_html(markdown_string).strip()
    root_elem = PyQuery(html)
    res = build_dict_from_sane_json(root_elem)
    expected = {'type': 'ul', 'contents': [
        {'type': 'li', 'attrs': [], 'layout': {}, 'extra': {},  # 0
         'contents': [
             {'type': 'span', 'contents': 'parent', 'attrs': [], 'layout': {},
              'extra': {}},
             {'type': 'ul', 'contents': [
                 {'type': 'li', 'attrs': [], 'layout': {}, 'extra': {},
                  'contents': 'child'}
             ], 'attrs': [], 'layout': {}, 'extra': {}}
         ]
         }], 'attrs': [], 'layout': {}, 'extra': {}
                }
    assert res == expected


def test_build_dict_ol():
    markdown_string = '1. parent\n\t1. child'
    html = markdown_to_html(markdown_string).strip()
    root_elem = PyQuery(html)
    res = build_dict_from_sane_json(root_elem)
    expected = {'type': 'ol', 'contents': [
        {'type': 'li', 'attrs': [], 'layout': {}, 'extra': {},  # 0
         'contents': [
             {'type': 'span', 'contents': 'parent', 'attrs': [], 'layout': {},
              'extra': {}},
             {'type': 'ol', 'contents': [
                 {'type': 'li', 'attrs': [], 'layout': {}, 'extra': {},
                  'contents': 'child'}
             ], 'attrs': [], 'layout': {}, 'extra': {}}
         ]
         }], 'attrs': [], 'layout': {}, 'extra': {}
                }
    assert res == expected


def test_build_dict_deep_ol():
    markdown_string = '1. parent\n\t1. child\n\t\t1. deep child'
    html = markdown_to_html(markdown_string).strip()
    root_elem = PyQuery(html)
    res = build_dict_from_sane_json(root_elem)
    expected = {'type': 'ol', 'contents': [
        {'type': 'li', 'attrs': [], 'layout': {}, 'extra': {},  # 0
         'contents': [
             {'type': 'span', 'contents': 'parent', 'attrs': [], 'layout': {},
              'extra': {}},
             {'type': 'ol', 'contents': [
                 {'type': 'li', 'attrs': [], 'layout': {}, 'extra': {},
                  'contents': [
                      {'type': 'span', 'contents': 'child', 'attrs': [],
                       'layout': {},
                       'extra': {}},
                      {'type': 'ol', 'contents': [
                          {'type': 'li', 'contents': 'deep child', 'attrs': [],
                           'layout': {},
                           'extra': {}},
                      ], 'attrs': [],
                       'layout': {},
                       'extra': {}},
                  ]}
             ], 'attrs': [], 'layout': {}, 'extra': {}}
         ]
         }], 'attrs': [], 'layout': {}, 'extra': {}
                }
    assert res == expected


def test_build_dict_basic_element_attribute():
    markdown_string = 'some [string](url)'
    html = markdown_to_html(markdown_string).strip()
    root_elem = PyQuery(html)
    res = build_dict_from_sane_json(root_elem)
    expected = {'type': 'p', 'contents': [
        {'type': 'span', 'contents': 'some ', 'attrs': [],
         'layout': {}, 'extra': {}},
        {'type': 'span', 'contents': [
            {'type': 'a', 'contents': 'string', 'attrs': [], 'layout': {},
             'extra': {'href': 'url'}}]
            , 'attrs': [], 'layout': {}, 'extra': {}}
    ], 'attrs': [], 'layout': {}, 'extra': {}
                }
    assert res == expected


def test_build_dict_text_and_elements():
    markdown_string = 'some **string** and more strings'
    html = markdown_to_html(markdown_string).strip()
    root_elem = PyQuery(html)
    res = build_dict_from_sane_json(root_elem)
    expected = {'type': 'p', 'contents': [

        {'type': 'span', 'contents': 'some ', 'attrs': [],
         'layout': {}, 'extra': {}},
        {'type': 'span', 'contents': [
            {'type': 'strong', 'contents': 'string', 'attrs': [],
             'layout': {}, 'extra': {}},
        ], 'attrs': [], 'layout': {}, 'extra': {}},
        {'type': 'span', 'contents': ' and more strings', 'attrs': [],
         'layout': {}, 'extra': {}},

    ], 'attrs': [], 'layout': {}, 'extra': {}
                }
    assert res == expected


def test_markdown_to_section_basic():
    markdown = '~~123~~'
    md_list = markdown_to_section_list(markdown)
    res = [i.get_dict() for i in md_list]
    expected = [{
        'type': 'p',
        'contents': [
            {
                'type': 'span',
                'attrs': ['strikethrough'],
                'extra': {},
                'contents': '123',
                'layout': {}
            }
        ], 'attrs': [], 'extra': {}, 'layout': {}
    }]
    assert res == expected


def test_markdown_to_section_wrapped():
    markdown = '**~~123~~**'
    md_list = markdown_to_section_list(markdown)

    res = [i.get_dict() for i in md_list]
    expected = [{'attrs': [],
                 'contents': [{'attrs': ['bold'],
                               'contents': [{'attrs': ['strikethrough'],
                                             'contents': '123',
                                             'extra': {},
                                             'layout': {},
                                             'type': 'span'}],
                               'extra': {},
                               'layout': {},
                               'type': 'span'}],
                 'extra': {},
                 'layout': {},
                 'type': 'p'}]
    assert res == expected


def test_markdown_to_section_pre_code():
    markdown = '\n```\ncode\n```\n'
    md_list = markdown_to_section_list(markdown)

    res = [i.get_dict() for i in md_list]
    expected = [{
        'type': 'pre',
        'contents': [
            {
                'type': 'code',
                'attrs': [],
                'extra': {},
                'contents': 'code',
                'layout': {}
            }
        ], 'attrs': [], 'extra': {}, 'layout': {}
    }]
    assert res == expected


def test_markdown_to_section_ul():
    markdown = '- one\n- *two*'
    md_list = markdown_to_section_list(markdown)

    res = [i.get_dict() for i in md_list]
    expected = [{
        'type': 'ul',
        'contents': [
            {'type': 'li', 'attrs': [], 'extra': {}, 'contents': 'one',
             'layout': {}},
            {'type': 'li', 'attrs': ['italic'], 'extra': {}, 'contents': 'two',
             'layout': {}}
        ], 'attrs': [], 'extra': {}, 'layout': {}
    }]
    assert res == expected


def test_markdown_to_section_ul_ol_complex():
    markdown = '- one\n- two\n\t1. nested\n\t2. nested deep'
    md_list = markdown_to_section_list(markdown)

    res = [i.get_dict() for i in md_list]
    expected = [{
        'type': 'ul',
        'contents': [
            {'type': 'li', 'attrs': [], 'extra': {}, 'contents': 'one',
             'layout': {}},
            {'type': 'li', 'attrs': [], 'extra': {}, 'contents': [
                {'type': 'span', 'attrs': [], 'extra': {}, 'contents': 'two',
                 'layout': {}},
                {'type': 'ol', 'attrs': [], 'extra': {}, 'contents': [
                    {'type': 'li', 'attrs': [], 'extra': {},
                     'contents': 'nested',
                     'layout': {}},
                    {'type': 'li', 'attrs': [], 'extra': {},
                     'contents': 'nested deep',
                     'layout': {}}
                ],
                 'layout': {}}
            ],
             'layout': {}},
        ], 'attrs': [], 'extra': {}, 'layout': {}
    }]
    assert res == expected


def test_markdown_to_section_list_quote():
    markdown_string = "> Blockquotes *can also* have ~~the~~ nested..."

    md_list = markdown_to_section_list(markdown_string)

    assert isinstance(md_list, list)
    assert isinstance(md_list[0], MarkdownSection)
    assert md_list[0].type == MD_TYPE_QUOTE

    res = [i.get_dict() for i in md_list]
    expected = [{
        'type': 'blockquote',
        'contents': [
            {
                'type': 'span', 'attrs': [], 'extra': {},
                'contents': 'Blockquotes ', 'layout': {}
            },
            {
                'type': 'span', 'attrs': ['italic'], 'extra': {},
                'contents': 'can also', 'layout': {}
            },
            {
                'type': 'span', 'attrs': [], 'extra': {},
                'contents': ' have ', 'layout': {}
            },
            {
                'type': 'span', 'attrs': ['strikethrough'], 'extra': {},
                'contents': 'the', 'layout': {}
            },
            {
                'type': 'span', 'attrs': [], 'extra': {},
                'contents': ' nested...', 'layout': {}
            }
        ], 'attrs': [], 'extra': {}, 'layout': {}
    }]
    assert res == expected


def test_build_dict_mdhtml_br():
    markdown_string = '<span>123<br>456<br />789</span>'
    html = markdown_to_html(markdown_string).strip()
    root_elem = PyQuery(html)
    res = build_dict_from_sane_json(root_elem)
    expected = {'attrs': [],
                'contents': [{'attrs': [],
                              'contents': [{'attrs': [],
                                            'contents': '123',
                                            'extra': {},
                                            'layout': {},
                                            'type': 'span'},
                                           {'attrs': [],
                                            'contents': '\n',
                                            'extra': {},
                                            'layout': {},
                                            'type': 'span'},
                                           {'attrs': [],
                                            'contents': '456',
                                            'extra': {},
                                            'layout': {},
                                            'type': 'span'},
                                           {'attrs': [],
                                            'contents': '\n',
                                            'extra': {},
                                            'layout': {},
                                            'type': 'span'},
                                           {'attrs': [],
                                            'contents': '789',
                                            'extra': {},
                                            'layout': {},
                                            'type': 'span'}],
                              'extra': {},
                              'layout': {},
                              'type': 'span'}],
                'extra': {},
                'layout': {},
                'type': 'p'}
    assert res == expected


def test_build_dict_mdhtml():
    markdown_string = '<span><b>one</b><strong>two</stong></span>'
    html = markdown_to_html(markdown_string).strip()
    root_elem = PyQuery(html)
    res = build_dict_from_sane_json(root_elem)
    expected = {'attrs': [],
                'contents': [{'attrs': [],
                              'contents': [{'attrs': [],
                                            'contents': [{'attrs': [],
                                                          'contents': 'one',
                                                          'extra': {},
                                                          'layout': {},
                                                          'type': 'strong'}],
                                            'extra': {},
                                            'layout': {},
                                            'type': 'span'},
                                           {'attrs': [],
                                            'contents': [{'attrs': [],
                                                          'contents': 'two',
                                                          'extra': {},
                                                          'layout': {},
                                                          'type': 'strong'}],
                                            'extra': {},
                                            'layout': {},
                                            'type': 'span'}],
                              'extra': {},
                              'layout': {},
                              'type': 'span'}],
                'extra': {},
                'layout': {}, 'type': 'p'}
    assert res == expected

