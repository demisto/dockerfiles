from subprocess import run
process = run(['/bin/sh', '-c', 'export NODE_PATH=$(npm root --quiet -g) && node /bake.js Test [] {}'], capture_output=True, text=True)
assert process.stdout == "Test\n"