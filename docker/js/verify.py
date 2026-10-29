"""
Verify the js image. Self-contained: every check is embedded here, nothing is read from content at test time.

Coverage is derived from a scan of all content JavaScript integrations/scripts (338 items) plus the
places that shell out to `node` (CyberChef bake.js/magic.js, demisto-sdk mdx-parse-server.js).
Each check pins exact output, so bumping the Node major version (24, 26, ...) fails on a named check
instead of breaking content at runtime.
"""

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
    """Run a script file the way CyberChef does: subprocess.run(["node", script, *json_args])."""
    process = subprocess.run(["node", write_file(script_name, source), *args], capture_output=True, text=True,
                             cwd=WORK_DIR, env=env)
    assert process.returncode == 0, f"{script_name} failed ({process.returncode}): {process.stderr}"
    return process.stdout.strip()


def check(script_name: str, source: str, expected: str, *args: str) -> None:
    output = run_node(script_name, source, *args)
    assert output == expected, f"{script_name}: expected {expected!r}, got {output!r}"
    print(f"[OK] {script_name}")


# Language and built-in behavior used by content JavaScript items. Usage counts (out of 338) from the scan.
# Each case: [name, function body returning a value, expected JSON-serialized result].
LANGUAGE_CASES = r"""
const cases = [
  // syntax (switch 125, try 93, for..in 59, let/const 31, arrows 19, template 20, for..of 10, default params 7, generators 2)
  ["switch fallthrough", () => { const out = []; for (const c of ["a", "b", "z"]) { switch (c) { case "a": out.push(1); case "b": out.push(2); break; default: out.push(0); } } return out; }, [1, 2, 2, 0]],
  ["try/catch/finally with thrown string", () => { const log = []; try { throw "boom"; } catch (e) { log.push(e); } finally { log.push("f"); } return log; }, ["boom", "f"]],
  ["for..in key order (integer keys first)", () => { const o = { b: 1, 2: 1, a: 1, 1: 1 }; const k = []; for (const x in o) k.push(x); return k; }, ["1", "2", "b", "a"]],
  ["let block scope in loop closures", () => { const fns = []; for (let i = 0; i < 3; i++) fns.push(() => i); return fns.map(f => f()); }, [0, 1, 2]],
  ["var hoisting", () => { function f() { x = 5; var x; return x; } return f(); }, 5],
  ["template literal multiline", () => `a
${1 + 1}`, "a\n2"],
  ["for..of over array", () => { let s = 0; for (const v of [1, 2, 3]) s += v; return s; }, 6],
  ["default params", () => { function f(a, b = 10) { return a + b; } return f(1); }, 11],
  ["generator", () => { function* g() { yield 1; yield 2; } return [...g()]; }, [1, 2]],
  ["arguments object", () => { function f() { return Array.prototype.slice.call(arguments).length; } return f(1, 2, 3); }, 3],
  ["destructuring + spread", () => { const [a, ...rest] = [1, 2, 3]; const { x, ...o } = { x: 1, y: 2 }; return [a, rest, x, o]; }, [1, [2, 3], 1, { y: 2 }]],
  ["labeled loop break", () => { let n = 0; outer: for (let i = 0; i < 3; i++) { for (let j = 0; j < 3; j++) { if (j === 1) continue outer; n++; } } return n; }, 3],
  ["typeof / instanceof / delete", () => { const o = { a: 1 }; delete o.a; return [typeof null, typeof undefined, typeof [], [] instanceof Array, "a" in o]; }, ["object", "undefined", "object", true, false]],
  ["prototype extension", () => { function P(n) { this.n = n; } P.prototype.get = function () { return this.n; }; return new P(4).get(); }, 4],
  ["getter/setter", () => { const o = { _v: 1, get v() { return this._v * 2; }, set v(x) { this._v = x; } }; o.v = 5; return o.v; }, 10],

  // JSON (parse 128, stringify 123)
  ["JSON.stringify ordering and spacing", () => JSON.stringify({ b: 1, a: [1, "x", null, true], 10: 0 }), '{"10":0,"b":1,"a":[1,"x",null,true]}'],
  ["JSON.stringify indent", () => JSON.stringify({ a: { b: 1 } }, null, 2), '{\n  "a": {\n    "b": 1\n  }\n}'],
  ["JSON.stringify drops undefined/functions, keeps unicode", () => JSON.stringify({ u: undefined, f() {}, h: "שלום", e: "\u2028" }), '{"h":"שלום","e":"\u2028"}'],
  ["JSON.stringify numbers", () => JSON.stringify([1e21, 0.1 + 0.2, -0, NaN, 1.5e-7]), "[1e+21,0.30000000000000004,0,null,1.5e-7]"],
  ["JSON.parse reviver and big ints", () => JSON.parse('{"a":"1","n":12345678901234567890}', (k, v) => k === "a" ? +v : v), { a: 1, n: 12345678901234567000 }],
  ["JSON.parse invalid throws SyntaxError", () => { try { JSON.parse("{bad"); return "no"; } catch (e) { return e instanceof SyntaxError; } }, true],

  // strings (split 115, indexOf 105, replace 83, case 65, substring 42, trim 36, match 26, substr 25, startsWith 13, includes 5)
  ["split with regex and limit", () => ["a, b,,c".split(/,\s*/), "a-b-c".split("-", 2), "".split(",")], [["a", "b", "", "c"], ["a", "b"], [""]]],
  ["replace with $ patterns and callback", () => ["john smith".replace(/(\w+)\s(\w+)/, "$2, $1"), "a.b.c".replace(/\./g, () => "/"), "x".replace("x", "$&$&")], ["smith, john", "a/b/c", "xx"]],
  ["replaceAll", () => "a.b.c".replaceAll(".", "-"), "a-b-c"],
  ["substr / substring / slice negatives", () => ["abcdef".substr(-3, 2), "abcdef".substring(4, 1), "abcdef".slice(-2)], ["de", "bcd", "ef"]],
  ["case conversion incl. unicode", () => ["straße".toUpperCase(), "İ".toLowerCase().length, "ÀB".toLowerCase()], ["STRASSE", 2, "àb"]],
  ["trim unicode whitespace", () => "\u00a0\ufeff x \n".trim(), "x"],
  ["indexOf/lastIndexOf/includes/startsWith", () => ["abcabc".indexOf("c", 3), "abcabc".lastIndexOf("a"), "abc".includes("bc"), "abc".startsWith("b", 1), "abc".endsWith("b", 2)], [5, 3, true, true, true]],
  ["match global vs non-global", () => ["a1b22".match(/\d+/g), "a1b22".match(/(\d)(\d)/).slice(0, 3), "x".match(/y/)], [["1", "22"], ["22", "2", "2"], null]],
  ["charCodeAt / fromCharCode / surrogate pairs", () => ["A".charCodeAt(0), String.fromCharCode(72, 105), "😀".length, [..."😀"].length], [65, "Hi", 2, 1]],
  ["localeCompare default", () => ["a", "B", "c"].sort((x, y) => x.localeCompare(y)), ["a", "B", "c"]],

  // regex (literals 92, new RegExp 16, named group 1, s flag 1)
  ["regex flags and lastIndex", () => { const r = /a/g; r.test("aa"); return [r.lastIndex, /A/i.test("a"), /^b/m.test("a\nb"), /a.b/s.test("a\nb")]; }, [1, true, true, true]],
  ["named groups and lookbehind", () => { const m = "2024-05-06".match(/(?<y>\d{4})-(?<m>\d\d)/); return [m.groups.y, m.groups.m, "$10".match(/(?<=\$)\d+/)[0]]; }, ["2024", "05", "10"]],
  ["new RegExp with escaped user input", () => new RegExp("a.b".replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).test("axb"), false],
  ["regex exec loop", () => { const r = /(\w)=(\d)/g; const out = []; let m; while ((m = r.exec("a=1,b=2")) !== null) out.push(m[1] + m[2]); return out; }, ["a1", "b2"]],
  ["IP and email style patterns", () => [/^(\d{1,3}\.){3}\d{1,3}$/.test("10.0.0.1"), /^[\w.+-]+@[\w-]+\.[\w.]+$/.test("a.b+c@d-e.com")], [true, true]],

  // arrays (push 159, Object.keys 99, forEach 74, isArray 60, map/filter/reduce 44, splice/slice 36, concat 27, sort 8)
  ["push/pop/shift/unshift", () => { const a = [2]; a.push(3); a.unshift(1); const p = a.pop(); const s = a.shift(); return [a, p, s]; }, [[2], 3, 1]],
  ["sort default is string order", () => [10, 9, 1, 100].sort(), [1, 10, 100, 9]],
  ["sort is stable", () => [{ k: 1, v: "a" }, { k: 0, v: "b" }, { k: 1, v: "c" }, { k: 0, v: "d" }].sort((x, y) => x.k - y.k).map(o => o.v).join(""), "bdac"],
  ["splice / slice / concat / reverse", () => { const a = [1, 2, 3, 4]; const r = a.splice(1, 2, "x"); return [a, r, [1].concat([2], 3), [1, 2].reverse(), a.slice(-1)]; }, [[1, "x", 4], [2, 3], [1, 2, 3], [2, 1], [4]]],
  ["map/filter/reduce/some/every/find", () => { const a = [1, 2, 3]; return [a.map(x => x * 2), a.filter(x => x % 2), a.reduce((s, x) => s + x, 0), a.some(x => x > 2), a.every(x => x > 0), a.find(x => x > 1), a.findIndex(x => x > 5)]; }, [[2, 4, 6], [1, 3], 6, true, true, 2, -1]],
  ["Array.isArray / Array.from / indexOf", () => [Array.isArray([]), Array.isArray({ length: 0 }), Array.from("ab"), Array.from({ length: 2 }, (_, i) => i), [1, 2].indexOf(3)], [true, false, ["a", "b"], [0, 1], -1]],
  ["sparse arrays and join", () => [[1, , 3].join("-"), [null, undefined, 1].join(","), new Array(3).length], ["1--3", ",,1", 3]],

  // objects (Object.keys 99, hasOwnProperty 14, Object.assign 4, Object.values/entries 3, Set/Map 1)
  ["Object.keys/values/entries/assign", () => { const o = Object.assign({}, { b: 2 }, { a: 1 }); return [Object.keys(o), Object.values(o), Object.entries(o)]; }, [["b", "a"], [2, 1], [["b", 2], ["a", 1]]]],
  ["hasOwnProperty vs inherited", () => { const o = Object.create({ inh: 1 }); o.own = 1; return [o.hasOwnProperty("own"), o.hasOwnProperty("inh"), "inh" in o]; }, [true, false, true]],
  ["Set and Map", () => { const s = new Set([1, 1, 2]); const m = new Map([["a", 1]]); return [s.size, [...s], m.get("a"), m.has("b")]; }, [2, [1, 2], 1, false]],

  // numbers (parseInt 58, isNaN 24, Math 26, parseFloat 9, Number 9)
  ["parseInt edge cases", () => [parseInt("08"), parseInt("0x1F"), parseInt("12px"), parseInt(""), parseInt("101", 2), parseInt(" 7 ")], [8, 31, 12, null, 5, 7]],
  ["parseFloat / Number / isNaN", () => [parseFloat("3.14abc"), Number(""), Number("12px"), isNaN("abc"), Number.isNaN("abc"), Number("0x10")], [3.14, 0, null, true, false, 16]],
  ["number formatting", () => [(0.1 + 0.2).toFixed(2), (1234.5).toString(), (255).toString(16), 1 / 3 + "", 2 ** 53 + 1], ["0.30", "1234.5", "ff", "0.3333333333333333", 9007199254740992]],
  ["Math functions", () => [Math.round(2.5), Math.round(-2.5), Math.floor(-1.1), Math.max(), Math.min(1, "2"), Math.abs(-3)], [3, -2, -2, null, 1, 3]],
  ["integer division and modulo", () => [7 % 3, -7 % 3, (7 / 2) | 0, 2 ** 31 | 0], [1, -1, 3, -2147483648]],

  // dates (new Date 54, getTime 39, toISOString 16, Date.parse 7, Date.now 5, toUTCString 5, getTimezoneOffset 4, toLocale 3)
  ["Date ISO round-trip", () => new Date("2024-01-15T10:20:30.123Z").toISOString(), "2024-01-15T10:20:30.123Z"],
  ["Date.parse ISO, date-only, RFC2822", () => [Date.parse("2024-01-15T00:00:00Z"), Date.parse("2024-01-15"), Date.parse("Mon, 15 Jan 2024 00:00:00 GMT")], [1705276800000, 1705276800000, 1705276800000]],
  ["Date.parse space-separated and invalid", () => [new Date("2024-01-15 10:20:30Z").getTime(), isNaN(Date.parse("not a date"))], [1705314030000, true]],
  ["Date UTC getters and arithmetic", () => { const d = new Date(Date.UTC(2024, 1, 29, 23, 0, 0)); d.setUTCDate(d.getUTCDate() + 1); return [d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), d.getUTCDay()]; }, [2024, 2, 1, 5]],
  ["Date toUTCString / toJSON", () => [new Date(0).toUTCString(), JSON.stringify({ d: new Date(0) })], ["Thu, 01 Jan 1970 00:00:00 GMT", '{"d":"1970-01-01T00:00:00.000Z"}']],
  ["Date.now and getTimezoneOffset are numbers", () => [typeof Date.now(), typeof new Date().getTimezoneOffset()], ["number", "number"]],
  ["toLocaleString en-US (ICU present)", () => [(1234567.891).toLocaleString("en-US"), new Date(0).toLocaleDateString("en-US", { timeZone: "UTC" })], ["1,234,567.891", "1/1/1970"]],

  // encoding (encodeURIComponent 21, btoa/atob 6, decodeURIComponent 1, encodeURI 1, unescape 1)
  ["encodeURIComponent / decodeURIComponent / encodeURI", () => [encodeURIComponent("a b&c=ד/?"), decodeURIComponent("%D7%93%20x"), encodeURI("http://x/a b?q=1&r=ש")], ["a%20b%26c%3D%D7%93%2F%3F", "ד x", "http://x/a%20b?q=1&r=%D7%A9"]],
  ["escape / unescape", () => [escape("a b+ü"), unescape("%u05D3%20")], ["a%20b+%FC", "ד "]],
  ["btoa / atob", () => [btoa("user:pass"), atob("dXNlcjpwYXNz")], ["dXNlcjpwYXNz", "user:pass"]],
  ["decodeURIComponent malformed throws URIError", () => { try { decodeURIComponent("%E0%A4%A"); return "no"; } catch (e) { return e instanceof URIError; } }, true],
];
const failures = [];
for (const [name, fn, expected] of cases) {
  let actual;
  try { actual = JSON.stringify(fn()); } catch (e) { actual = "THREW " + e; }
  if (actual !== JSON.stringify(expected)) failures.push(`${name}: expected ${JSON.stringify(expected)}, got ${actual}`);
}
console.log(JSON.stringify({ total: cases.length, failures }));
"""

# Content JS runs as a function body with server-injected globals (178/338 use top-level `return`).
# This harness replays the content patterns against mocks of those globals: args (3395 uses), command (1062),
# params (934), http (566), executeCommand (164), tableToMarkdown (228), entryTypes/formats, context, setIntegrationContext.
CONTENT_RUNTIME_HARNESS = r"""
const vm = require("vm");
const calls = [];
let integrationContext = {};
function makeGlobals(overrides) {
  return Object.assign({
    args: {}, params: { url: "https://api.example.com", insecure: false }, command: "test-module",
    context: {}, incidents: [], incident: { id: "1" }, investigation: { id: "inv" },
    entryTypes: { note: 1, error: 4 }, formats: { json: "json", markdown: "markdown", text: "text" },
    http: (url, req, insecure, proxy) => { calls.push(["http", url, req.Method, insecure]); return { StatusCode: 200, Status: "200 OK", Body: JSON.stringify({ items: [{ id: 1, name: "a" }, { id: 2, name: "b" }] }), Headers: {} }; },
    executeCommand: (cmd, cmdArgs) => { calls.push(["executeCommand", cmd]); return [{ Type: 1, Contents: { ok: true, args: cmdArgs } }]; },
    tableToMarkdown: (title, rows, headers) => `### ${title}\n|${headers.join("|")}|\n` + rows.map(r => "|" + headers.map(h => r[h]).join("|") + "|").join("\n"),
    encodeToURLQuery: (o) => "?" + Object.keys(o).map(k => encodeURIComponent(k) + "=" + encodeURIComponent(o[k])).join("&"),
    getIntegrationContext: () => integrationContext, setIntegrationContext: (c) => { integrationContext = c; },
    logDebug: () => {}, logInfo: () => {}, logError: () => {}, log: () => {},
    isError: (e) => e && e.Type === 4, dq: (obj, path) => path.split(".").reduce((o, k) => (o || {})[k], obj),
  }, overrides);
}
// The server compiles content code as a function body; vm + wrapper reproduces that contract under Node.
function runContent(code, overrides) {
  const sandbox = vm.createContext(makeGlobals(overrides));
  return vm.runInContext("(function(){\n" + code + "\n})()", sandbox, { timeout: 5000 });
}

const integration = `
var baseUrl = params.url.replace(/[\\/]+$/, '');
function sendRequest(method, path, body) {
    var res = http(baseUrl + path + encodeToURLQuery(args), { Method: method, Headers: { 'Content-Type': ['application/json'] }, Body: body ? JSON.stringify(body) : undefined }, params.insecure);
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request Failed. Status code: ' + res.StatusCode + '. Body: ' + JSON.stringify(res);
    }
    try { return JSON.parse(res.Body); } catch (err) { throw 'Failed to parse response: ' + err; }
}
switch (command) {
    case 'test-module':
        sendRequest('GET', '/ping');
        return 'ok';
    case 'example-list':
        var items = sendRequest('GET', '/items').items;
        var ctx = { 'Example.Item(val.id && val.id === obj.id)': items };
        return { Type: entryTypes.note, Contents: items, ContentsFormat: formats.json,
                 HumanReadable: tableToMarkdown('Items', items, ['id', 'name']), EntryContext: ctx };
    case 'fetch-incidents':
        var last = getIntegrationContext().last || 0;
        var newItems = sendRequest('GET', '/items').items.filter(function (i) { return i.id > last; });
        var incs = newItems.map(function (i) { return { name: 'Item ' + i.id, rawJSON: JSON.stringify(i), occurred: new Date(0).toISOString() }; });
        setIntegrationContext({ last: newItems.length ? newItems[newItems.length - 1].id : last });
        return JSON.stringify(incs);
    default:
        throw 'Unknown command: ' + command;
}`;

const script = `
var res = executeCommand('getIncidents', { query: args.query });
if (isError(res[0])) { return res; }
var values = (args.value || '').split(',').map(function (v) { return v.trim(); }).filter(Boolean);
var unique = values.filter(function (v, i, a) { return a.indexOf(v) === i; });
return { Type: entryTypes.note, ContentsFormat: formats.json, Contents: unique,
         EntryContext: { UniqueValues: unique, Query: dq(res[0], 'Contents.args.query') } };`;

const results = {
  testModule: runContent(integration, { command: "test-module" }),
  list: runContent(integration, { command: "example-list", args: { limit: 2 } }),
  fetch1: runContent(integration, { command: "fetch-incidents" }),
  fetch2: runContent(integration, { command: "fetch-incidents" }),
  script: runContent(script, { args: { value: "a, b,a,,c", query: "status:1" } }),
  unknown: (() => { try { runContent(integration, { command: "nope" }); } catch (e) { return String(e); } })(),
  calls,
};
console.log(JSON.stringify(results));
"""

EXPECTED_RUNTIME_RESULTS = {
    "testModule": "ok",
    "list": {
        "Type": 1,
        "Contents": [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}],
        "ContentsFormat": "json",
        "HumanReadable": "### Items\n|id|name|\n|1|a|\n|2|b|",
        "EntryContext": {"Example.Item(val.id && val.id === obj.id)": [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]},
    },
    "fetch1": json.dumps([
        {"name": "Item 1", "rawJSON": '{"id":1,"name":"a"}', "occurred": "1970-01-01T00:00:00.000Z"},
        {"name": "Item 2", "rawJSON": '{"id":2,"name":"b"}', "occurred": "1970-01-01T00:00:00.000Z"},
    ], separators=(",", ":")),
    "fetch2": "[]",
    "script": {"Type": 1, "ContentsFormat": "json", "Contents": ["a", "b", "c"],
               "EntryContext": {"UniqueValues": ["a", "b", "c"], "Query": "status:1"}},
    "unknown": "Unknown command: nope",
    "calls": [
        ["http", "https://api.example.com/ping?", "GET", False],
        ["http", "https://api.example.com/items?limit=2", "GET", False],
        ["http", "https://api.example.com/items?", "GET", False],
        ["http", "https://api.example.com/items?", "GET", False],
        ["executeCommand", "getIncidents"],
    ],
}


def verify_node_version() -> str:
    version = subprocess.check_output(["node", "--version"], text=True).strip()
    assert version.startswith(f"v{EXPECTED_NODE_MAJOR}."), f"Expected Node.js {EXPECTED_NODE_MAJOR}, got {version}"
    print(f"[OK] node version {version}")
    return version


def verify_language_behavior() -> None:
    report = json.loads(run_node("language_cases.js", LANGUAGE_CASES))
    assert not report["failures"], "Language behavior changed:\n  " + "\n  ".join(report["failures"])
    print(f"[OK] language behavior ({report['total']} cases)")


def verify_content_runtime() -> None:
    results = json.loads(run_node("content_runtime.js", CONTENT_RUNTIME_HARNESS))
    for key, expected in EXPECTED_RUNTIME_RESULTS.items():
        assert results[key] == expected, f"content runtime [{key}]: expected {expected!r}, got {results[key]!r}"
    print("[OK] content runtime (function-body wrapper + server globals)")


def verify_content_syntax_rules() -> None:
    """Syntax shapes content relies on: top-level return inside the wrapper, sloppy mode, legacy octal escapes."""
    check("sloppy_mode.js", r"""
const vm = require("vm");
const bodies = ["return 1;", "x = 2; return x;", "return 010 + '\\101';", "with ({a: 3}) { return a; }"];
console.log(bodies.map(b => vm.runInNewContext("(function(){\n" + b + "\n})()")).join(","));
""", "1,2,8A,3")
    process = subprocess.run(["node", "-e", "new (require('vm').Script)('return 1;')"], capture_output=True, text=True)
    assert process.returncode != 0 and "Illegal return" in process.stderr, "top-level return must require the wrapper"
    print("[OK] top-level return rejected without wrapper")


def verify_cyberchef_usage() -> None:
    """CyberChef bake.js/magic.js: JSON args via argv, async/await, NODE_PATH require, stderr for errors."""
    check("argv_json.js", """
async function run(input, recipe = "[]", options = "{}") {
    const parsed = await Promise.resolve({ input, recipe: JSON.parse(recipe), options: JSON.parse(options) });
    console.log(JSON.stringify(parsed));
}
run(process.argv[2], process.argv[3], process.argv[4]);
""", json.dumps({"input": "One, two", "recipe": ["to decimal"], "options": {}}, separators=(",", ":")),
        "One, two", json.dumps(["to decimal"]), json.dumps({}))

    process = subprocess.run(["node", "-e", "console.error('Error:', new Error('boom')); console.log('out')"],
                             capture_output=True, text=True)
    assert process.stdout.strip() == "out" and "boom" in process.stderr, "stdout/stderr separation broken"
    print("[OK] stderr separation")

    write_file("global_modules/fake-chef/package.json", json.dumps({"name": "fake-chef", "main": "index.js"}))
    write_file("global_modules/fake-chef/index.js", "exports.bake = async (input) => input.toUpperCase();")
    output = run_node("node_path.js", "require('fake-chef').bake('chef').then(console.log);",
                      env={**os.environ, "NODE_PATH": os.path.join(WORK_DIR, "global_modules")})
    assert output == "CHEF", f"NODE_PATH require failed: {output!r}"
    print("[OK] NODE_PATH require")


def verify_mdx_server_usage() -> None:
    """demisto-sdk mdx-parse-server.js: require() of ESM-only @mdx-js/mdx v3, http server with POST body + url.parse."""
    write_file("esm_only.mjs", "export const compile = (text) => `compiled:${text}`;")
    check("require_esm.js", "const { compile } = require('./esm_only.mjs'); console.log(compile('md'));", "compiled:md")
    check("import_esm.mjs", "import { compile } from './esm_only.mjs'; console.log(compile('md'));", "compiled:md")
    check("http_server.js", """
const http = require('http');
const url = require('url');
const server = http.createServer((req, res) => {
    const query = url.parse(req.url, true).query;
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (data) => { body += data; });
    req.on('end', () => {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ body, fix: query.fix }));
    });
});
server.listen(0, '127.0.0.1', async () => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/?fix=true`, { method: 'POST', body: '# Title' });
    console.log(JSON.stringify(await response.json()));
    server.close();
});
""", json.dumps({"body": "# Title", "fix": "true"}, separators=(",", ":")))


def verify_process_io() -> None:
    """Core modules, UTF-8 output and large stdout through the subprocess pipe."""
    check("core_modules.js", """
const fs = require('fs'), path = require('path'), os = require('os'), zlib = require('zlib'), crypto = require('crypto');
const file = path.join(os.tmpdir(), 'js-verify.txt');
fs.writeFileSync(file, 'שלום');
const roundtrip = zlib.gunzipSync(zlib.gzipSync(fs.readFileSync(file))).toString('utf8');
const digests = ['md5', 'sha1', 'sha256'].map(a => crypto.createHash(a).update(Buffer.from('abc')).digest('hex').slice(0, 8));
console.log(`${roundtrip}|${digests.join(',')}`);
""", "שלום|90015098,a9993e36,ba7816bf")

    large_output = run_node("large_output.js", "process.stdout.write('x'.repeat(5 * 1024 * 1024));")
    assert len(large_output) == 5 * 1024 * 1024, "large stdout was truncated"
    print("[OK] large stdout")


node_version = verify_node_version()
verify_language_behavior()
verify_content_syntax_rules()
verify_content_runtime()
verify_cyberchef_usage()
verify_mdx_server_usage()
verify_process_io()
print(f"All is good. Node.js {node_version} passed all js image checks.")
