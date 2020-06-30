import arrow
import pytest
from arrow.parser import ParserError

from sane_doc_reports.utils import get_formatted_date, has_anomalies


def test_get_formatted_date():
    default_date_format = {'format': 'MMMM Do YYYY, h:mm:ss a Z'}
    formatted_date = get_formatted_date('2012-12-18', default_date_format)

    assert formatted_date == "December 18th 2012, 12:00:00 am +0000"

    default_date_format = {'format': 'DD MMM Y'}
    formatted_date = get_formatted_date('2012-12-18', default_date_format)

    assert formatted_date == "18 Dec Y"


def test_get_formatted_date_iso():
    default_date_format = ''
    formatted_date = get_formatted_date('2012-12-18', default_date_format)

    assert formatted_date == "2012-12-18T00:00:00+00:00"


def test_get_formatted_date_now():
    default_date_format = {'format': 'DD MMM YYYY'}
    formatted_date = get_formatted_date('', default_date_format)

    now = arrow.now()
    assert formatted_date == now.format(default_date_format['format'])


def test_get_formatted_date_now_iso():
    default_date_format = ''
    formatted_date = get_formatted_date('', default_date_format)

    now = arrow.now()
    assert formatted_date[0:10] == now.isoformat()[0:10]


def test_get_formatted_date_invalid():
    default_date_format = ''
    with pytest.raises(ParserError):
        get_formatted_date('wowowowow', default_date_format)


def test_has_anomalies():
    no_anoms = [1, 1, 1, 1, 1]
    assert has_anomalies(no_anoms) is False
    no_anoms = [1, 2, 1, 2, 1]
    assert has_anomalies(no_anoms) is False

    almost_anoms = [1, 10, 1, 2, 1]
    assert has_anomalies(almost_anoms) is False

    yes_anoms = [1, 11, 1, 2, 1]
    assert has_anomalies(yes_anoms) is True
    yes_anoms = [1, 200, 1, 2, 1]
    assert has_anomalies(yes_anoms) is True
    yes_anoms = [1, 200, 100, 200, 1]
    assert has_anomalies(yes_anoms) is True
