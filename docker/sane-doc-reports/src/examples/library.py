from sane_doc_reports import main
from sane_doc_reports.conf import XSOAR_LOGO_BASE64
from tests.utils import get_mock


def example_basic(out_file_name='example.docx'):
    main.run(get_mock('grid_checks/fullgrid.json', ret_dict=False),
             out_file_name)


def example_paged(out_file_name='example.docx'):
    main.run(get_mock('grid_checks/fullgridpaged.json', ret_dict=False),
             out_file_name)


def example_paged_complex(out_file_name='example.docx'):
    main.run(get_mock('grid_checks/complexpaged.json', ret_dict=False),
             out_file_name)


def example_table(out_file_name='example.docx'):
    main.run(get_mock('elements/table.json', ret_dict=False), out_file_name)


def example_table_new(out_file_name='example.docx'):
    main.run(get_mock('elements/table_new_json.json', ret_dict=False),
             out_file_name)


def example_number_and_trend(out_file_name='example.docx'):
    main.run(get_mock('elements/number_and_trend.json', ret_dict=False),
             out_file_name)


def example_text(out_file_name='example.docx'):
    main.run(get_mock('elements/text.json', ret_dict=False), out_file_name)


def example_pie_chart(out_file_name='example.docx'):
    main.run(get_mock('elements/pie_chart.json', ret_dict=False),
             out_file_name)


def example_markdown(out_file_name='example.docx'):
    main.run(get_mock('elements/markdown.json', ret_dict=False), out_file_name)


def example_markdown_md_button(out_file_name='example.docx'):
    main.run(get_mock('elements/markdown_md_button.json', ret_dict=False),
             out_file_name)


def example_markdown_paged(out_file_name='example.docx'):
    main.run(get_mock('elements/markdown_paged.json', ret_dict=False),
             out_file_name)


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


def example_orientation_landscape(out_file_name='example.docx'):
    main.run(get_mock('grid_checks/fullgrid.json', ret_dict=False),
             out_file_name, {'orientation': 'landscape'})


def example_paper_size_a3(out_file_name='example.docx'):
    main.run(get_mock('grid_checks/fullgrid.json', ret_dict=False),
             out_file_name, {'paper_size': 'A3'})


def example_list(out_file_name='example.docx'):
    main.run(get_mock('elements/list.json', ret_dict=False), out_file_name)


def example_date(out_file_name='example.docx'):
    main.run(get_mock('elements/date.json', ret_dict=False), out_file_name)


def example_items_section(out_file_name='example.docx'):
    main.run(get_mock('elements/items_section.json', ret_dict=False),
             out_file_name)


def example_image_remote(out_file_name='example.docx'):
    main.run(get_mock('elements/image-remote.json', ret_dict=False),
             out_file_name)


def example_image_svg(out_file_name='example.docx'):
    main.run(get_mock('elements/image-svg.json', ret_dict=False), out_file_name)


def example_header_logo(out_file_name='example.docx'):
    main.run(get_mock('grid_checks/fullgrid.json', ret_dict=False),
             out_file_name, options={
            'customerLogo': XSOAR_LOGO_BASE64,
            'demistoLogo': XSOAR_LOGO_BASE64
        })


def example():
    main.run(get_mock('example.json', ret_dict=False), 'example.docx')


def example_all():
    examples = [
        example_basic,
        example_paged,
        example_table,
        example_table_new,
        example_number_and_trend,
        example_text,
        example_pie_chart,
        example_markdown,
        example_markdown_md_button,
        example_markdown_paged,
        example_hr,
        example_old_json,
        example_bar_chart,
        example_duration,
        example_line_chart,
        example_unimplemented,
        example_items_section,
        example_header_logo
    ]
    for out_index, fun in enumerate(examples):
        out_file_name = f'example_{out_index}.docx'
        fun(out_file_name)


def run():
    example()


if __name__ == '__main__':
    run()
