from subprocess import run
process = run(['/bin/sh', '-c', 'node /bake.js Test [] {}'], capture_output=True, text=True)
assert process.stdout == "Test\n"
process = run(['/bin/sh', '-c', 'node /magic.js "4f 6e 65 2c 20 74 77 6f 2c 20 74 68 72 65 65 2c 20 66 6f 75 72 2e" {}'], capture_output=True, text=True)
assert process.stdout