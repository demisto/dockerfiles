import subprocess
# make sure soffice is installed correctly
subprocess.check_output(["soffice", "--version"], text=True)
import openpyxl
from docx import Document
from pptx import Presentation