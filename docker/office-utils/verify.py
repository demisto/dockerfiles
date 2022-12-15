import subprocess
# make sure soffice is installed correctly
subprocess.check_output(["soffice", "--version"], text=True)