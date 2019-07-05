from sane_doc_reports import main
from tests.utils import get_mock


def example_basic(out_file_name='example.docx'):
    main.run(get_mock('grid_checks/fullgrid.json', ret_dict=False),
             out_file_name)


def example_table(out_file_name='example.docx'):
    main.run(get_mock('elements/table.json', ret_dict=False), out_file_name)


def example_number(out_file_name='example.docx'):
    main.run(get_mock('elements/number_and_trend.json', ret_dict=False),
             out_file_name)


def example_text(out_file_name='example.docx'):
    main.run(get_mock('elements/text.json', ret_dict=False), out_file_name)


def example_pie_chart(out_file_name='example.docx'):
    main.run(get_mock('elements/pie_chart.json', ret_dict=False),
             out_file_name)


def example_markdown(out_file_name='example.docx'):
    main.run(get_mock('elements/markdown.json', ret_dict=False), out_file_name)


def example_hr(out_file_name='example.docx'):
    main.run(get_mock('elements/hr.json', ret_dict=False), out_file_name)


def example_line_chart(out_file_name='example.docx'):
    main.run(get_mock('elements/line_chart.json', ret_dict=False),
             out_file_name)


def example_old_json(out_file_name='example.docx'):
    main.run(get_mock('old_json.json', ret_dict=False),
             out_file_name)


def _example_junk(out_file_name='example.docx'):
    # Generate a big elements file for testing
    main.run(get_mock('junkbig.json', ret_dict=False), out_file_name)


def example_bar_chart(out_file_name='example.docx'):
    main.run(get_mock('elements/bar_chart.json', ret_dict=False),
             out_file_name)


def example_duration(out_file_name='example.docx'):
    main.run(get_mock('elements/duration.json', ret_dict=False), out_file_name)


def example_unimplemented(out_file_name='example.docx'):
    main.run(get_mock('elements/unimplemented.json', ret_dict=False),
             out_file_name)


def example():
    main.run(get_mock('example.json', ret_dict=False), 'example.docx')


def run_all():
    examples = [
        example_basic,
        example_table,
        example_number,
        example_text,
        example_pie_chart,
        example_markdown,
        example_hr,
        example_old_json,
        example_bar_chart,
        example_duration,
        example_line_chart,
        example_unimplemented
    ]
    for out_index, fun in enumerate(examples):
        out_file_name = f'example_{out_index}.docx'
        fun(out_file_name)


def run():
    example()


if __name__ == '__main__':
    run()
