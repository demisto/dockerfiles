import subprocess
subprocess.check_output(["unrar", "--version"], text=True)
subprocess.check_output(["7z"], text=True)
print('unzip is good!!!')