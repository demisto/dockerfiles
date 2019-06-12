from sane_doc_reports.populate.Report import Report
from sane_doc_reports.transform.Transform import Transform


def run(sane_json_path: str, docx_output_path: str) -> None:
    """
    Create a elements report main invoker.
    Steps:
    1) Transform: get the JSON and transform to Sections and Wrappers.
    2) Populate: Send the Sections and Wrappers to Report, and populate it.
    3) Save: Save the generated file on disk.
    """

    # Transform
    transformer = Transform(sane_json_path)
    pages = transformer.get_pages()
    transformed_sane_json = transformer.get_sane_json()

    # Populate
    report = Report(pages, transformed_sane_json)
    report.populate_report()

    # Save
    report.save(docx_output_path)
