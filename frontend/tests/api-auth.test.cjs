const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const ts = require("typescript");
const source = ts.transpileModule(fs.readFileSync(require("node:path").join(__dirname, "../lib/api.ts"), "utf8"), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 }
}).outputText;
function setup(status = 200, body = {}) {
  const values = new Map([["avighna_token", "test-session-only"], ["avighna_user", "{}"]]);
  const calls = [], redirects = [];
  const context = { exports: {}, process: { env: {} }, URL, Headers, Error,
    window: { localStorage: { getItem: k => values.get(k), removeItem: k => values.delete(k) },
      location: { assign: p => redirects.push(p) } },
    fetch: async (url, init) => { calls.push({ url, init }); return new Response(JSON.stringify(body), { status }); }
  };
  vm.runInNewContext(source, context);
  return { apiFetch: context.exports.apiFetch, values, calls, redirects };
}
test("attaches token to configured API origin", async () => {
  const s = setup(); await s.apiFetch("/devices/");
  assert.equal(s.calls[0].url, "http://127.0.0.1:8000/devices/");
  assert.equal(s.calls[0].init.headers.get("Authorization"), "Bearer test-session-only");
});
test("rejects other origins before sending credentials", async () => {
  const s = setup(); await assert.rejects(s.apiFetch("https://example.com/devices/"), /another API origin/);
  assert.equal(s.calls.length, 0);
});
test("authentication failure clears stale credentials without showing login", async () => {
  const s = setup(401); await assert.rejects(s.apiFetch("/devices/"), /requires authentication/);
  assert.equal(s.values.size, 0); assert.deepEqual(s.redirects, []);
});
test("permission failure preserves session and reports error", async () => {
  const s = setup(403, { detail: "Permission denied" });
  await assert.rejects(s.apiFetch("/actions/quarantine"), /Permission denied/);
  assert.equal(s.values.size, 2); assert.equal(s.redirects.length, 0);
});

test("local viewing works without a stored token", async () => {
  const s = setup(); s.values.clear(); await s.apiFetch("/devices/");
  assert.equal(s.calls[0].init.headers.get("X-AVIGHNA-Local-View"), "1");
  assert.equal(s.calls[0].init.headers.get("Authorization"), null);
  assert.equal(s.redirects.length, 0);
});
