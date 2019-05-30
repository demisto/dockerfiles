from sane_doc_reports.cli import main
from click.testing import CliRunner


def test_help():
    runner = CliRunner()
    result = runner.invoke(main, ['--help'])
    assert result.exit_code == 0
    assert 'Show this message and exit' in result.output

