"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  PROTOCOLS,
  installInteropExplorer,
  protocolView,
} = require("../../docs/assets/interoperability.js");

const root = path.resolve(__dirname, "../..");

class FakeElement {
  constructor(value = "") {
    this.value = value;
    this.textContent = "";
    this.children = [];
    this.listeners = new Map();
  }

  addEventListener(type, callback) {
    this.listeners.set(type, callback);
  }

  replaceChildren(...children) {
    this.children = children;
  }

  dispatch(type) {
    this.listeners.get(type)?.();
  }
}

function fakeDocument() {
  const ids = [
    "interop-product",
    "interop-wire",
    "interop-bindings",
    "interop-negative",
    "interop-source",
  ];
  const elements = Object.fromEntries(ids.map((id) => [id, new FakeElement()]));
  elements["interop-protocol"] = new FakeElement("oidc");
  return {
    elements,
    getElementById(id) {
      return elements[id] || null;
    },
    createElement() {
      return new FakeElement();
    },
  };
}

test("profile maps all four real products to success and rejection evidence", () => {
  assert.deepEqual(Object.keys(PROTOCOLS), ["oidc", "saml", "ldap", "kerberos"]);
  for (const protocol of Object.values(PROTOCOLS)) {
    assert.ok(protocol.product);
    assert.ok(protocol.wire.length >= 4);
    assert.match(protocol.negative, /拒否/u);
    assert.match(protocol.source, /authlab\//u);
  }
});

test("explorer rerenders the selected protocol without synthetic credentials", () => {
  const document = fakeDocument();
  const explorer = installInteropExplorer(document);
  assert.equal(explorer.selected(), "oidc");
  assert.equal(document.elements["interop-wire"].children.length, 4);
  assert.equal(document.elements["interop-product"].textContent, "Keycloak 26.7.0");

  document.elements["interop-protocol"].value = "kerberos";
  document.elements["interop-protocol"].dispatch("change");
  assert.equal(explorer.selected(), "kerberos");
  assert.match(document.elements["interop-bindings"].textContent, /service principal/u);
  for (const element of Object.values(document.elements)) {
    assert.doesNotMatch(element.textContent, /fixture-only-password/u);
  }
});

test("unknown protocol is rejected", () => {
  assert.throws(() => protocolView("unknown"), RangeError);
});

test("Pages markup states the Docker boundary and exposes an accessible control", () => {
  const html = fs.readFileSync(path.join(root, "docs/index.html"), "utf8");
  assert.match(html, /id="t-interop" class="tab-panel"/u);
  assert.match(html, /role="tab"[^>]*aria-controls="t-interop"/u);
  assert.match(html, /id="interop-protocol"/u);
  assert.match(html, /id="interop-product"[^>]*aria-live="polite"/u);
  assert.match(html, /Pages上ではDockerを起動しません/u);
  assert.match(html, /run_interop\.py --start/u);
});
