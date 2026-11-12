// Verify the js image: Node version, core modules, the content execution model, and existing node usages.
const assert = require('assert');
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const EXPECTED_NODE_MAJOR = '22';
const WORK_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-'));

function writeFile(relativePath, source) {
  const filePath = path.join(WORK_DIR, relativePath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, source);
  return filePath;
}

// Each check runs in a fresh node process, like content does
function check(scriptName, source, expected, { args = [], env = process.env } = {}) {
  const output = execFileSync(process.execPath, [writeFile(scriptName, source), ...args], { cwd: WORK_DIR, env, encoding: 'utf8' }).trim();
  assert.strictEqual(output, expected, `${scriptName}: expected ${expected}, got ${output}`);
  console.log(`[OK] ${scriptName}`);
}

// 1. Node major version
assert.ok(process.version.startsWith(`v${EXPECTED_NODE_MAJOR}.`), `Expected Node.js ${EXPECTED_NODE_MAJOR}, got ${process.version}`);
console.log(`[OK] node version ${process.version}`);

// 2. Core modules load (the "import" check other images do for their libraries)
check('core_modules.js', `
const modules = ['fs', 'path', 'os', 'http', 'https', 'url', 'vm', 'crypto', 'zlib', 'child_process', 'util'];
modules.forEach((name) => require(name));
const hash = require('crypto').createHash('sha256').update('abc').digest('hex').slice(0, 8);
console.log(\`\${modules.length}|\${hash}\`);
`, '11|ba7816bf');

// 3. Content execution model: code runs as a function body (top-level return) with server-injected globals
check('content_runtime.js', String.raw`
const vm = require('vm');
const calls = [];
const globals = {
  command: 'example-list', args: { limit: '2' }, params: { url: 'https://api.example.com/' },
  entryTypes: { note: 1 }, formats: { json: 'json' },
  http: (url, req) => { calls.push(req.Method + ' ' + url); return { StatusCode: 200, Body: '{"items":[{"id":1},{"id":2}]}' }; },
};
const contentCode = "var res = http(params.url.replace(/\\/+$/, '') + '/items?limit=' + args.limit, { Method: 'GET' });\n" +
  "if (res.StatusCode !== 200) { throw 'Request failed: ' + res.StatusCode; }\n" +
  "switch (command) {\n" +
  "  case 'example-list':\n" +
  "    return { Type: entryTypes.note, ContentsFormat: formats.json, Contents: JSON.parse(res.Body).items };\n" +
  "  default:\n" +
  "    throw 'Unknown command: ' + command;\n" +
  "}";
const result = vm.runInContext('(function(){\n' + contentCode + '\n})()', vm.createContext(globals), { timeout: 5000 });
console.log(JSON.stringify({ result, calls }));
`, JSON.stringify({
  result: { Type: 1, ContentsFormat: 'json', Contents: [{ id: 1 }, { id: 2 }] },
  calls: ['GET https://api.example.com/items?limit=2'],
}));

// 4a. CyberChef bake.js/magic.js: JSON args via argv, async/await, require through NODE_PATH
writeFile('global_modules/fake-chef/package.json', JSON.stringify({ name: 'fake-chef', main: 'index.js' }));
writeFile('global_modules/fake-chef/index.js', 'exports.bake = async (input, recipe) => `${input.toUpperCase()}|${recipe[0]}`;');
check('cyberchef_style.js', `
const chef = require('fake-chef');
async function run(input, recipe = '[]') { console.log(await chef.bake(input, JSON.parse(recipe))); }
run(process.argv[2], process.argv[3]);
`, 'ONE|to decimal', {
  args: ['one', JSON.stringify(['to decimal'])],
  env: { ...process.env, NODE_PATH: path.join(WORK_DIR, 'global_modules') },
});

// 4b. demisto-sdk mdx-parse-server.js: require() of an ESM-only package, http server with POST body and url.parse
writeFile('esm_only.mjs', 'export const compile = (text) => `compiled:${text}`;');
check('mdx_server_style.js', `
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
  const response = await fetch(\`http://127.0.0.1:\${server.address().port}/?fix=true\`, { method: 'POST', body: '# Title' });
  console.log(JSON.stringify(await response.json()));
  server.close();
});
`, JSON.stringify({ compiled: 'compiled:# Title', fix: 'true' }));

console.log(`All is good. Node.js ${process.version} passed all js image checks.`);
