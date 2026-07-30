"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  DEFAULT_SOURCE,
  browserIncompatibleModule,
} = require("../../docs/assets/pyodide-policy.js");
const {
  WORKER_URL,
  createWorkerClient,
} = require("../../docs/assets/pyodide-lab.js");

const root = path.resolve(__dirname, "../..");

class FakeWorker {
  constructor() {
    this.listeners = new Map();
    this.messages = [];
    this.terminated = false;
  }

  addEventListener(type, listener) {
    this.listeners.set(type, listener);
  }

  postMessage(message) {
    this.messages.push(message);
  }

  respond(message) {
    this.listeners.get("message")?.({ data: message });
  }

  terminate() {
    this.terminated = true;
  }
}

test("JWT preset runs real authlab issue, validate, tamper, and refusal paths", () => {
  assert.match(DEFAULT_SOURCE, /from authlab\.jose import/u);
  assert.match(DEFAULT_SOURCE, /issuer\.issue/u);
  assert.match(DEFAULT_SOURCE, /validator\.validate\(token\)/u);
  assert.match(DEFAULT_SOURCE, /validator\.validate\(forged\)/u);
  assert.match(DEFAULT_SOURCE, /TAMPERED: REFUSED/u);
});

test("browser-incompatible socket, ssl, and mTLS imports are guarded", () => {
  for (const source of [
    "import socket",
    "import ssl as tls",
    "from authlab.mtls import MTLSServer",
    "from authlab.crypto.x509 import Certificate",
  ]) {
    const result = browserIncompatibleModule(source);
    assert.ok(result, source);
    assert.match(result.message, /drills\/12_mtls\.py/u);
  }
  assert.equal(browserIncompatibleModule("from authlab.jose import JWT"), null);
});

test("worker client correlates concurrent success and failure responses", async () => {
  const worker = new FakeWorker();
  const client = createWorkerClient(worker);
  const initialized = client.initialize();
  const executed = client.execute("print('hello')");
  assert.deepEqual(worker.messages.map(({ id, type }) => ({ id, type })), [
    { id: 1, type: "initialize" },
    { id: 2, type: "execute" },
  ]);
  worker.respond({ id: 2, ok: true, result: "hello\n" });
  worker.respond({
    id: 1,
    ok: false,
    error: { name: "NetworkError", message: "offline" },
  });
  assert.equal(await executed, "hello\n");
  await assert.rejects(initialized, { name: "NetworkError", message: "offline" });
  client.terminate();
  assert.equal(worker.terminated, true);
});

test("markup preserves a light initial page and exposes accessible REPL controls", () => {
  const html = fs.readFileSync(path.join(root, "docs/index.html"), "utf8");
  const worker = fs.readFileSync(path.join(root, "docs/assets/pyodide-worker.js"), "utf8");
  assert.equal(WORKER_URL, "assets/pyodide-worker.js");
  assert.doesNotMatch(html, /cdn\.jsdelivr\.net\/pyodide/u);
  assert.match(worker, /cdn\.jsdelivr\.net\/pyodide\/v\$\{PYODIDE_VERSION\}/u);
  assert.match(html, /id="t-pyodide" class="tab-panel"/u);
  assert.match(html, /id="pyodide-source"[^>]*aria-describedby="pyodide-help"/u);
  assert.match(html, /id="pyodide-source"[^>]*aria-keyshortcuts="Control\+Enter Meta\+Enter"/u);
  assert.match(html, /id="pyodide-status"[^>]*role="status"[^>]*aria-live="polite"/u);
  assert.match(html, /id="pyodide-output"[^>]*aria-live="polite"/u);
  assert.match(html, /id="pyodide-run"[^>]*type="button"/u);
  assert.match(html, /class="tabs" role="tablist"/u);
  assert.match(html, /role="tab" aria-selected="false" aria-controls="t-pyodide"/u);
  const css = fs.readFileSync(path.join(root, "docs/assets/lab.css"), "utf8");
  assert.match(css, /@media \(max-width: 640px\)[^]*\.pyodide-actions/u);
  assert.match(css, /min-height: 44px/u);
  assert.match(css, /nav\.tabs[^]*flex-wrap: nowrap/u);
  assert.match(css, /overflow-x: auto/u);
});

test("tab dispatcher is the only automatic trigger for lazy Pyodide initialization", () => {
  const lab = fs.readFileSync(path.join(root, "docs/assets/lab.js"), "utf8");
  const pyodide = fs.readFileSync(path.join(root, "docs/assets/pyodide-lab.js"), "utf8");
  assert.match(lab, /authlab:tabshown/u);
  assert.match(lab, /event\.key === "ArrowRight"/u);
  assert.match(lab, /window\.location\.hash/u);
  assert.match(lab, /revealSelectedTab/u);
  assert.match(lab, /window\.addEventListener\("resize"/u);
  assert.match(pyodide, /event\.detail\?\.id === "t-pyodide"/u);
  assert.doesNotMatch(pyodide, /DOMContentLoaded[^]*ensureInitialized/u);
});
