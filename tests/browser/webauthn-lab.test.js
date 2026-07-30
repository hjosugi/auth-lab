"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  base64urlDecode,
  base64urlEncode,
  decodeCbor,
  derEcdsaToRaw,
  parseAuthenticatorData,
  validateClientData,
} = require("../../docs/assets/webauthn-lab.js");

const root = path.resolve(__dirname, "../..");

test("base64url encoding round-trips binary credential IDs without padding", () => {
  const input = Uint8Array.from([0, 1, 2, 127, 128, 254, 255]);
  const encoded = base64urlEncode(input);
  assert.doesNotMatch(encoded, /[+/=]/u);
  assert.deepEqual(base64urlDecode(encoded), input);
});

test("minimal CBOR decoder handles attestation map key shapes and signed COSE labels", () => {
  const value = decodeCbor(Uint8Array.from([
    0xa3,
    0x63, 0x66, 0x6d, 0x74, 0x64, 0x6e, 0x6f, 0x6e, 0x65,
    0x01, 0x02,
    0x20, 0x42, 0xaa, 0xbb,
  ]));
  assert.equal(value.get("fmt"), "none");
  assert.equal(value.get(1), 2);
  assert.deepEqual(value.get(-1), Uint8Array.from([0xaa, 0xbb]));
});

test("authenticator flags expose UP, UV, backup eligibility, backup state, and counter", () => {
  const data = new Uint8Array(37);
  data[32] = 0x01 | 0x04 | 0x08 | 0x10;
  new DataView(data.buffer).setUint32(33, 42, false);
  const parsed = parseAuthenticatorData(data);
  assert.equal(parsed.userPresent, true);
  assert.equal(parsed.userVerified, true);
  assert.equal(parsed.backupEligible, true);
  assert.equal(parsed.backupState, true);
  assert.equal(parsed.signCount, 42);
  data[32] = 0x01 | 0x10;
  assert.throws(() => parseAuthenticatorData(data), /without backup eligibility/u);
});

test("client data validation rejects origin, challenge, and ceremony type mismatches", () => {
  const challenge = Uint8Array.from([1, 2, 3]);
  const valid = {
    type: "webauthn.get",
    challenge: base64urlEncode(challenge),
    origin: "http://localhost:8080",
  };
  assert.doesNotThrow(() => validateClientData(valid, {
    type: "webauthn.get",
    challenge,
    origin: "http://localhost:8080",
  }));
  assert.throws(
    () => validateClientData(valid, { type: "webauthn.get", challenge, origin: "https://lookalike.invalid" }),
    /Origin binding failed/u,
  );
  assert.throws(
    () => validateClientData(valid, { type: "webauthn.create", challenge, origin: valid.origin }),
    /ceremony type/u,
  );
  assert.throws(
    () => validateClientData(valid, {
      type: valid.type,
      challenge: Uint8Array.from([9]),
      origin: valid.origin,
    }),
    /Challenge binding failed/u,
  );
});

test("DER ECDSA signatures become fixed-width Web Crypto signatures", () => {
  const raw = derEcdsaToRaw(Uint8Array.from([
    0x30, 0x46,
    0x02, 0x21, 0x00, ...new Array(32).fill(0x80),
    0x02, 0x21, 0x00, ...new Array(32).fill(0x81),
  ]));
  assert.equal(raw.length, 64);
  assert.deepEqual(raw.slice(0, 32), new Uint8Array(32).fill(0x80));
  assert.deepEqual(raw.slice(32), new Uint8Array(32).fill(0x81));
});

test("native WebAuthn markup is keyboard operable and announces ceremony results", () => {
  const html = fs.readFileSync(path.join(root, "docs/index.html"), "utf8");
  const css = fs.readFileSync(path.join(root, "docs/assets/lab.css"), "utf8");
  assert.match(html, /id="t-webauthn-native" class="tab-panel"/u);
  assert.match(html, /id="webauthn-status"[^>]*role="status"[^>]*aria-live="polite"/u);
  for (const id of [
    "webauthn-register",
    "webauthn-authenticate",
    "webauthn-discoverable",
    "webauthn-origin-negative",
    "webauthn-rpid-negative",
  ]) {
    assert.match(html, new RegExp(`id="${id}"[^>]*type="button"`, "u"));
  }
  assert.match(css, /button\.act:focus-visible/u);
  assert.match(html, /Attestation:/u);
  assert.match(html, /Sign counter:/u);
  assert.match(html, /Sync \/ backup:/u);
});
