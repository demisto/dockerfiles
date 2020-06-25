import fastjsonschema
from sane_doc_reports.conf import DATA_KEY, LAYOUT_KEY, ROW_POSITION_KEY, \
    COL_POSITION_KEY, HEIGHT_POSITION_KEY, WIDTH_POSITION_KEY

validate = fastjsonschema.compile({
    'type': 'array',
    'items': {
        'type': 'object',
        'required': ['type', f'{DATA_KEY}', f'{LAYOUT_KEY}'],
        'properties': {
            'type': {'type': 'string'},
            f'{DATA_KEY}': {
                'type': ['object', 'array', 'string', 'integer'],
                'items': {
                    'type': 'object',
                    'properties': {
                        'text': {'type': 'string'}
                    }
                }
            },
            f'{LAYOUT_KEY}': {
                'type': 'object',
                'required': [f'{ROW_POSITION_KEY}', f'{COL_POSITION_KEY}',
                             f'{HEIGHT_POSITION_KEY}', f'{WIDTH_POSITION_KEY}'],
                'properties': {
                    f'{ROW_POSITION_KEY}': {'type': 'integer', "minimum": 0},
                    f'{COL_POSITION_KEY}': {'type': 'integer', "minimum": 0},
                    f'{HEIGHT_POSITION_KEY}': {'type': 'integer', "minimum": 1},
                    f'{WIDTH_POSITION_KEY}': {'type': 'integer', "minimum": 1},
                }
            },
        },
    }
})
