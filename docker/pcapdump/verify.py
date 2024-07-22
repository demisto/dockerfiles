import subprocess
from hexdump2 import hexdump

dump = hexdump("Test", result="return")
with open("test", 'w') as t:
        t.writelines([dump])

subprocess.run(
    [
        "/bin/sh",
        "-c",
        "text2pcap -T 1337,80 -4 10.0.0.2,10.0.0.3 test test.pcap"
    ],
    shell=False,
)