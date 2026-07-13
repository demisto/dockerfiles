from subprocess import Popen, PIPE

command = "flarestrings requirements.txt | rank_strings --scores"

process = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
stdout, stderr = process.communicate()

if process.returncode != 0:
    raise Exception("verification failed")
if stderr:
    raise Exception(f"rank_strings produced stderr output: {stderr.decode(errors='replace')}")

print("Successfully executed stringsifter command")
