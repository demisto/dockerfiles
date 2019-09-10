from sane_doc_reports.conf import ROW_POSITION_KEY, COL_POSITION_KEY, LAYOUT_KEY
from tests.utils import _transform


def test_sane_json_null_values():
    json = _transform('invalid/null_values.json')
    assert json[1].json_data[0][LAYOUT_KEY][ROW_POSITION_KEY] == 0
    assert json[1].json_data[0][LAYOUT_KEY][COL_POSITION_KEY] == 0