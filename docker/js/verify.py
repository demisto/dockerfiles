"""Verify the js image: Node version, core modules, the content execution model, and existing node usages."""

import json
import os
import subprocess
import tempfile

EXPECTED_NODE_MAJOR = "22"
WORK_DIR = tempfile.mkdtemp()


def write_file(relative_path: str, source: str) -> str:
    path = os.path.join(WORK_DIR, relative_path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as file:
        file.write(source)
    return path


def run_node(script_name: str, source: str, *args: str, env: dict | None = None) -> str:
    process = subprocess.run(["node", write_file(script_name, source), *args], capture_output=True, text=True,
                             cwd=WORK_DIR, env=env)
    assert process.returncode == 0, f"{script_name} failed ({process.returncode}): {process.stderr}"
    return process.stdout.strip()


def check(script_name: str, source: str, expected: str, *args: str, env: dict | None = None) -> None:
    output = run_node(script_name, source, *args, env=env)
    assert output == expected, f"{script_name}: expected {expected!r}, got {output!r}"
    print(f"[OK] {script_name}")


# 1. Node major version
version = subprocess.check_output(["node", "--version"], text=True).strip()
assert version.startswith(f"v{EXPECTED_NODE_MAJOR}."), f"Expected Node.js {EXPECTED_NODE_MAJOR}, got {version}"
print(f"[OK] node version {version}")

# 2. Core modules load (the "import" check other images do for their libraries)
check("core_modules.js", """
const modules = ['fs', 'path', 'os', 'http', 'https', 'url', 'vm', 'crypto', 'zlib', 'child_process', 'util'];
modules.forEach((name) => require(name));
const hash = require('crypto').createHash('sha256').update('abc').digest('hex').slice(0, 8);
console.log(`${modules.length}|${hash}`);
""", "11|ba7816bf")

# 3. Content execution model: code runs as a function body (top-level return) with server-injected globals
check("content_runtime.js", r"""
const vm = require('vm');
const calls = [];
const globals = {
  command: 'example-list', args: { limit: '2' }, params: { url: 'https://api.example.com/' },
  entryTypes: { note: 1 }, formats: { json: 'json' },
  http: (url, req) => { calls.push(`${req.Method} ${url}`); return { StatusCode: 200, Body: '{"items":[{"id":1},{"id":2}]}' }; },
};
const contentCode = `
var res = http(params.url.replace(/\\/+$/, '') + '/items?limit=' + args.limit, { Method: 'GET' });
if (res.StatusCode !== 200) { throw 'Request failed: ' + res.StatusCode; }
switch (command) {
    case 'example-list':
        return { Type: entryTypes.note, ContentsFormat: formats.json, Contents: JSON.parse(res.Body).items };
    default:
        throw 'Unknown command: ' + command;
}`;
const result = vm.runInContext('(function(){\n' + contentCode + '\n})()', vm.createContext(globals), { timeout: 5000 });
console.log(JSON.stringify({ result, calls }));
""", json.dumps({"result": {"Type": 1, "ContentsFormat": "json", "Contents": [{"id": 1}, {"id": 2}]},
                 "calls": ["GET https://api.example.com/items?limit=2"]}, separators=(",", ":")))

# 4a. CyberChef bake.js/magic.js: JSON args via argv, async/await, require through NODE_PATH
write_file("global_modules/fake-chef/package.json", json.dumps({"name": "fake-chef", "main": "index.js"}))
write_file("global_modules/fake-chef/index.js", "exports.bake = async (input, recipe) => `${input.toUpperCase()}|${recipe[0]}`;")
check("cyberchef_style.js", """
const chef = require('fake-chef');
async function run(input, recipe = '[]') { console.log(await chef.bake(input, JSON.parse(recipe))); }
run(process.argv[2], process.argv[3]);
""", "ONE|to decimal", "one", json.dumps(["to decimal"]),
      env={**os.environ, "NODE_PATH": os.path.join(WORK_DIR, "global_modules")})

# 4b. demisto-sdk mdx-parse-server.js: require() of an ESM-only package, http server with POST body and url.parse
write_file("esm_only.mjs", "export const compile = (text) => `compiled:${text}`;")
check("mdx_server_style.js", """
const http = require('http');
const url = require('url');
const { compile } = require('./esm_only.mjs');
const server = http.createServer((req, res) => {
    const query = url.parse(req.url, true).query;
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (data) => { body += data; });
    req.on('end', () => res.end(JSON.stringify({ compiled: compile(body), fix: query.fix })));
});
server.listen(0, '127.0.0.1', async () => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/?fix=true`, { method: 'POST', body: '# Title' });
    console.log(JSON.stringify(await response.json()));
    server.close();
});
""", json.dumps({"compiled": "compiled:# Title", "fix": "true"}, separators=(",", ":")))

print(f"All is good. Node.js {version} passed all js image checks.")
