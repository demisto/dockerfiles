from sane_doc_reports.populate.Report import Report
from sane_doc_reports.transform.utils import transform_old_json_format
from tests.utils import _transform


def test_transform_old_json_no_col_row():
    test_json = [{
        'type': 'text',
        'data': '',
        'layout': {},
    }]
    transformed = transform_old_json_format(test_json)
    expected = [{
        'type': 'text',
        'data': {'text': ''},
        'layout': {
            'rowPos': 0,
            'columnPos': 0,
            'w': 10,
            'h': 1
        }
    }]
    assert transformed == expected


def test_transform_old_json_multiple_rows():
    test_json = [{
        'type': 'text',
        'data': '',
        'layout': {},
    }, {
        'type': 'text',
        'data': '123',
        'layout': {
            'rowPos': 100,
            'columnPos': 0,
        },
    }, {
        'type': 'text',
        'data': '123',
        'layout': {
            'rowPos': 100,
            'columnPos': 2,
        }
    },
        {
            'type': 'text',
            'data': '123',
            'layout': {
                'rowPos': 200,
                'columnPos': 8,
            }
        }
    ]
    transformed = transform_old_json_format(test_json)
    expected = [{
        'type': 'text',
        'data': {'text': ''},
        'layout': {
            'rowPos': 0,
            'columnPos': 0,
            'w': 10,
            'h': 1
        },
    }, {
        'type': 'text',
        'data': {'text': '123'},
        'layout': {
            'rowPos': 1,
            'columnPos': 0,
            'w': 5,
            'h': 1
        },
    }, {
        'type': 'text',
        'data': {'text': '123'},
        'layout': {
            'rowPos': 1,
            'columnPos': 5,
            'w': 5,
            'h': 1
        }
    },
        {
            'type': 'text',
            'data': {'text': '123'},
            'layout': {
                'rowPos': 2,
                'columnPos': 0,
                'w': 10,
                'h': 1
            }
        }
    ]
    assert transformed == expected


def test_old_json():
    '''
        To check the xpath: rename the .elements to .zip and
         open word/document.xml
    '''
    report = Report(*_transform('old_json.json'))
    report.populate_report()

    d = report.document

    # Find 1 fonts, we also have default one which is different
    assert len(d.element.xpath('//w:t')) == 107

    # One red text
    assert len(d.element.xpath(
        "//w:color[@w:val='FF1744']/following::w:t[position() < 2]")) == 1

    # Find HRs
    assert len(d.element.xpath("//w:jc[@w:val='center']")) == 2

    # Find tables
    assert len(d.element.xpath('//w:tbl')) == 5
