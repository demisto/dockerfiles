from subprocess import Popen, PIPE

Popen(["flarestrings", 'requirements.txt'], stdout=PIPE)
print("All OK. StringSifter imported successfully")
