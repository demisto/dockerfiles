# Sane Doc Reports by [Demisto](https://demisto.com)

An extension to [sane-reports](https://github.com/demisto/sane-reports), 
> *"keep you sane and not pulling your hair out while generating DOCX reports"*

## Installation
*This project uses Python 3*  
`pipenv install sane-doc-reports`

## Usage
**CLI**  
First, generate a JSON file with the sane-reports repo.
```sh
$ sane-doc some.json -w out.docx # Not implemented yet. Use the library.
```

**Library**
```
import sane_doc_reports
```

## Development
1) Install the mypy addon for your IDE
2) Dev:
```sh
$ pipenv install --dev
$ pipenv shell
$ pytest # For testing
$ pytest --cov=sane_doc_reports # For coverage
```

### Terminology
1) Grid Layout - all of the docs are created in a table so we could position them.
2) CellObject - corresponds to a cell when the element will be inserted into
3) Section - Usually an element that we will place into a cell (has a type, contents (which can be more sections), layout (style and position), extra (metadata used mainly in recursive stuff), attrs (hold any markdown attributes generated from the html generated)).
4) Element - a `python-docx` implementation of an element from the sane-reports.
5) Styles - Element styles.
6) elements/md_* - Markdown generated elements
7) Wrapper - Holds one or more elements inside, usually to color the background / indent (lists)
8) SaneJson - holds the raw sane-json sections.


### Generating JSON files
1) Start a new demisto server with: `report.remove.data=false`
2) Go to the reports, generate a desired report
3) Get the json from `<demisto_path>/debug/lib/temp`

To check how it looks in the sane-reports:
1) Change the `incidentDailyReportTempalte.json` file with the json from the last step (in `lib/temp`)
2) `npm run start`
3) To mark the tables there you can open the console and add this:
```js
document.body.innerHTML += "<style>.report-layout .react-grid-layout .react-grid-item{border: 1px solid grey;}</sctyle>"
```

### How to add new docx elements (text, tables, charts...)
1) Create a file in the sane_doc_reports/docx folder with the same name as the 
type in the sane json file.
2) Every docx element/wrapper should implement a `invoke(cell_object, section):` function.  
The function needs to create an instance of the same class in the file (see the docx/text.py file for example).  
You can create an Element (text, hr...) or a Wrapper (which holds other elements, quote, ul...).  
Wrappers usually call markdown again (to create more wrappers/elements inside the same cell object).

### Docker usage:
1) Generate a `whl` file:
`python3 setup.py sdist bdist_wheel`
2) Copy to the .dockerfile directory and add to `copy` command