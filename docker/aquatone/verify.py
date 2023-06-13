from subprocess import Popen, PIPE
cmd = ['aquatone-discover', '--domain', 'example.com']
p = Popen(cmd, stdout=PIPE, stderr=PIPE, encoding="utf-8")
stdout, stderr = p.communicate()
print("All is good. aquatone-discover initialized")

