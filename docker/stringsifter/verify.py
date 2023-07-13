from subprocess import Popen, PIPE

command = "flarestrings requirements.txt"

process = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
stdout, stderr = process.communicate()

return_code = process.returncode
if return_code != 0:
    raise Exception("verification failed")

print("Successfully executed stringsifter command")