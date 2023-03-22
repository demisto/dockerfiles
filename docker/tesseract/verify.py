import subprocess
# make sure tesseract is running
subprocess.check_output(["tesseract", "--version", "--list-langs"], text=True)