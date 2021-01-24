# Sane Doc Reports by [Demisto](https://demisto.com)
An extension to [sane-reports](https://github.com/demisto/sane-reports), 
> *"keep you sane and not pulling your hair out while generating DOCX reports"*
## Usage
**CLI**  
First, generate a JSON file with the sane-reports repo.
Then do `Instalation` phase 5, to change the example ouput, place your json in the `tests/mock_data/example.json` file and make sure that `examples/library.py` is running `example()` in the `run` method.
**Library**
```
import sane_doc_reports
```
## Development & Installation
1) Install pyenv python 3.8.2
2) `sudo npm install svgexport -g  --unsafe-perm=true`
2) Dev:
```sh
$ pipenv install --dev -e .
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
### Generating JSON files (in demisto)
1) Start a new demisto server with: `report.remove.data=false`
2) Go to the reports, generate a desired report
3) Get the json from `<demisto_path>/debug/lib/temp`
To check how it looks in the sane-reports:
1) Change the `DailyReportTempalte.json` file with the json from the last step (in `lib/temp`)
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
### Docker update:
1) Clone the https://github.com/demisto/dockerfiles
2) cd to `dockerfiles/docker/sane-doc-reports/`
3) Remove the src dir `rm -r ./src`
4) Clone the new updates `git clone git@github.com:demisto/sane-doc-reports.git src` or with a specific branch: `git clone git@github.com:demisto/sane-doc-reports.git -b <branch name> src`
5) Remove unnecessary dirs: `rm -rf ./src/.gt ./src/.circleci`
6) Build the docker image: `DOCKER_ORG=devdemisto ./build_docker.sh sane-doc-reports` (from the docker dir)
7) Go to demisto: https://localhost:8443/#/automation find the `SaneDocReports` automation and change the docker image to the one you just generated.
### How to update the sane-doc-reports docker tag
1) Go to Automations in Demisto
2) Search for "SaneDocReports"
3) Copy it, and Go to settings
4) Chagne the docker image (probably need to `docker pull` before)
5) Change the `reports.docx.script` to the name of the new script.
### Demisto specific Settings
`reports.docx.script` - the custom SaneDocReport automation name (default: ``)  
`report.remove.data` - keep the json when generating a report.