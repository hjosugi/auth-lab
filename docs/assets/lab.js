/* auth-lab playground engine.
 *
 * Every demo here runs entirely in the browser using the Web Crypto API, so
 * the cryptography is real, not faked -- the same SHA-256, HMAC, PBKDF2, and
 * ECDSA the Python library leans on, exposed through window.crypto.subtle.
 * No network calls, no external libraries. Open the page offline and it works.
 */
"use strict";

/* ------------------------------------------------------------------ */
/* encoding helpers                                                    */
/* ------------------------------------------------------------------ */

const enc = new TextEncoder();
const dec = new TextDecoder();

function bytesToB64url(bytes) {
  let bin = "";
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlToBytes(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlToText(str) {
  try { return dec.decode(b64urlToBytes(str)); } catch (e) { return "(not valid base64url text)"; }
}

function hex(bytes) {
  return Array.from(new Uint8Array(bytes)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/* ------------------------------------------------------------------ */
/* 1. base64url playground                                            */
/* ------------------------------------------------------------------ */

function demoBase64() {
  const input = document.getElementById("b64-input").value;
  const encoded = bytesToB64url(enc.encode(input));
  document.getElementById("b64-encoded").textContent = encoded;
  document.getElementById("b64-note").textContent =
    `${enc.encode(input).length} bytes -> ${encoded.length} chars. Note: no '=' padding, '-' and '_' instead of '+' and '/'. This is the alphabet every JWT segment uses.`;
}

function demoBase64Decode() {
  const input = document.getElementById("b64-decode-input").value.trim();
  document.getElementById("b64-decoded").textContent = b64urlToText(input);
}

/* ------------------------------------------------------------------ */
/* 2. JWT decoder + HS256 verify + alg=none demo                      */
/* ------------------------------------------------------------------ */

function decodeJwt() {
  const token = document.getElementById("jwt-input").value.trim();
  const parts = token.split(".");
  const out = document.getElementById("jwt-decoded");
  if (parts.length !== 3) {
    out.innerHTML = `<span class="bad">A compact JWT has exactly 3 dot-separated segments; this has ${parts.length}.</span>`;
    return;
  }
  let header, payload;
  try {
    header = JSON.parse(b64urlToText(parts[0]));
    payload = JSON.parse(b64urlToText(parts[1]));
  } catch (e) {
    out.innerHTML = `<span class="bad">Could not parse header/payload as JSON.</span>`;
    return;
  }
  const warn = [];
  if ((header.alg || "").toLowerCase() === "none")
    warn.push("alg=none: this token is UNSIGNED. A verifier that trusts the header's alg would accept a forgery.");
  if (header.jwk || header.jku || header.x5u)
    warn.push("header carries a key (jwk/jku/x5u): a verifier that follows it lets the token pick its own key.");
  if (payload.exp) {
    const secs = payload.exp - Math.floor(Date.now() / 1000);
    warn.push(secs > 0 ? `exp: valid for ${secs} more seconds.` : `exp: EXPIRED ${-secs} seconds ago.`);
  }
  if (!payload.aud) warn.push("no aud claim: nothing stops this token being replayed at a different API.");

  out.innerHTML =
    `<div class="jwt-seg jwt-h"><b>header</b>\n${JSON.stringify(header, null, 2)}</div>` +
    `<div class="jwt-seg jwt-p"><b>payload</b>\n${JSON.stringify(payload, null, 2)}</div>` +
    `<div class="jwt-seg jwt-s"><b>signature</b>\n${parts[2]}\n(${b64urlToBytes(parts[2]).length} bytes, opaque)</div>` +
    (warn.length ? `<div class="note">${warn.map(w => "• " + w).join("<br>")}</div>` : "");
}

async function jwtSignVerify() {
  const secret = document.getElementById("jwt-secret").value;
  const payloadText = document.getElementById("jwt-payload").value;
  const out = document.getElementById("jwt-signverify");
  let payloadObj;
  try { payloadObj = JSON.parse(payloadText); } catch (e) {
    out.innerHTML = `<span class="bad">payload is not valid JSON</span>`; return;
  }
  const header = { alg: "HS256", typ: "JWT" };
  const signingInput = bytesToB64url(enc.encode(JSON.stringify(header))) + "." +
    bytesToB64url(enc.encode(JSON.stringify(payloadObj)));
  const key = await crypto.subtle.importKey("raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(signingInput));
  const token = signingInput + "." + bytesToB64url(sig);

  // verify with the right secret, and demonstrate a wrong secret failing
  const ok = await crypto.subtle.verify("HMAC", key, sig, enc.encode(signingInput));
  const wrongKey = await crypto.subtle.importKey("raw", enc.encode(secret + "x"),
    { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  const bad = await crypto.subtle.verify("HMAC", wrongKey, sig, enc.encode(signingInput));

  out.innerHTML =
    `<div class="mono wrap">${token}</div>` +
    `<div class="note">verify with correct secret: <span class="good">${ok}</span> · ` +
    `verify with wrong secret: <span class="${bad ? "bad" : "good"}">${bad}</span></div>`;
  document.getElementById("jwt-input").value = token;
}

function forgeAlgNone() {
  const payloadText = document.getElementById("jwt-payload").value;
  let payloadObj;
  try { payloadObj = JSON.parse(payloadText); } catch (e) { payloadObj = { sub: "admin" }; }
  payloadObj.sub = "admin";
  payloadObj.role = "superuser";
  const header = { alg: "none", typ: "JWT" };
  const forged = bytesToB64url(enc.encode(JSON.stringify(header))) + "." +
    bytesToB64url(enc.encode(JSON.stringify(payloadObj))) + ".";
  document.getElementById("jwt-input").value = forged;
  decodeJwt();
  document.getElementById("jwt-attack-note").innerHTML =
    `Forged an <b>alg=none</b> token claiming <code>sub=admin, role=superuser</code> with an empty signature. ` +
    `A naive verifier that reads <code>alg</code> from the token and switches on it accepts this. ` +
    `authlab refuses it because the caller must pass an explicit algorithm allow-list and 'none' is never in it.`;
}

/* ------------------------------------------------------------------ */
/* 3. TOTP (RFC 6238) using HMAC-SHA1 via Web Crypto                  */
/* ------------------------------------------------------------------ */

function base32Decode(s) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  s = s.replace(/=+$/, "").toUpperCase().replace(/\s/g, "");
  let bits = 0, value = 0;
  const out = [];
  for (const c of s) {
    const idx = alphabet.indexOf(c);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(out);
}

async function computeTotp(secretBytes, counter, digits) {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(4, counter >>> 0, false);
  view.setUint32(0, Math.floor(counter / 2 ** 32), false);
  const key = await crypto.subtle.importKey("raw", secretBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));
  const offset = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return (bin % 10 ** digits).toString().padStart(digits, "0");
}

let totpTimer = null;
async function startTotp() {
  const secretInput = document.getElementById("totp-secret").value.trim() || "JBSWY3DPEHPK3PXP";
  const secret = base32Decode(secretInput);
  const period = 30, digits = 6;
  async function tick() {
    const now = Math.floor(Date.now() / 1000);
    const counter = Math.floor(now / period);
    const code = await computeTotp(secret, counter, digits);
    const remaining = period - (now % period);
    document.getElementById("totp-code").textContent = code.slice(0, 3) + " " + code.slice(3);
    document.getElementById("totp-remaining").textContent = `${remaining}s until it rotates`;
    document.getElementById("totp-bar").style.width = (remaining / period * 100) + "%";
  }
  if (totpTimer) clearInterval(totpTimer);
  await tick();
  totpTimer = setInterval(tick, 1000);
  document.getElementById("totp-note").innerHTML =
    "This is a live RFC 6238 TOTP, computed with HMAC-SHA1 in your browser. " +
    "Add it to Google Authenticator with the secret above and the codes match. " +
    "The server accepts a code once, remembers the step, and refuses replays.";
}

async function verifyRfcVector() {
  // RFC 6238 Appendix B: secret "12345678901234567890", t=59, 8 digits -> 94287082
  const secret = enc.encode("12345678901234567890");
  const code = await computeTotp(secret, Math.floor(59 / 30), 8);
  document.getElementById("totp-vector").innerHTML =
    `RFC 6238 vector (t=59, 8 digits): got <b>${code}</b>, expected <b>94287082</b> — ` +
    `<span class="${code === "94287082" ? "good" : "bad"}">${code === "94287082" ? "match" : "MISMATCH"}</span>`;
}

/* ------------------------------------------------------------------ */
/* 4. PKCE                                                            */
/* ------------------------------------------------------------------ */

async function generatePkce() {
  const verifier = bytesToB64url(randomBytes(32));
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(verifier));
  const challenge = bytesToB64url(digest);
  document.getElementById("pkce-verifier").textContent = verifier;
  document.getElementById("pkce-challenge").textContent = challenge;
  document.getElementById("pkce-note").innerHTML =
    "The <b>verifier</b> stays on the client. Only the <b>challenge</b> (its SHA-256) travels through the browser " +
    "on the /authorize request. At the token endpoint the client sends the verifier; the server re-hashes it and compares. " +
    "An attacker who steals the code from the redirect cannot produce the verifier, because SHA-256 does not run backwards.";
}

async function verifyPkce() {
  const verifier = document.getElementById("pkce-check-verifier").value.trim();
  const challenge = document.getElementById("pkce-verifier-target").textContent ||
    document.getElementById("pkce-challenge").textContent;
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(verifier));
  const computed = bytesToB64url(digest);
  const stored = document.getElementById("pkce-challenge").textContent;
  const match = computed === stored && stored.length > 0;
  document.getElementById("pkce-verify-result").innerHTML =
    stored.length === 0 ? "Generate a pair first." :
    `SHA-256(your verifier) ${match ? "==" : "!="} stored challenge — ` +
    `<span class="${match ? "good" : "bad"}">${match ? "PKCE OK, code accepted" : "PKCE FAILED, code rejected"}</span>`;
}

/* ------------------------------------------------------------------ */
/* 5. Password hashing (PBKDF2 via Web Crypto) + timing              */
/* ------------------------------------------------------------------ */

async function pbkdf2Hash(password, salt, iterations) {
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" }, keyMaterial, 256));
}

async function hashPassword() {
  const password = document.getElementById("pw-input").value;
  const iterations = parseInt(document.getElementById("pw-iter").value, 10) || 100000;
  const salt = randomBytes(16);
  const t0 = performance.now();
  const digest = await pbkdf2Hash(password, salt, iterations);
  const dt = performance.now() - t0;
  document.getElementById("pw-output").innerHTML =
    `<div class="mono wrap">$pbkdf2-sha256$i=${iterations}$${bytesToB64url(salt)}$${bytesToB64url(digest)}</div>` +
    `<div class="note">${dt.toFixed(0)} ms per hash. Higher iterations = slower for you AND for an attacker's dictionary. ` +
    `That deliberate slowness is the point. scrypt/Argon2 add a memory cost on top, which is what actually hurts GPUs.</div>`;
}

async function demoTiming() {
  const salt = randomBytes(16);
  const stored = await pbkdf2Hash("real-password", salt, 100000);
  const out = document.getElementById("pw-timing");
  out.textContent = "measuring...";
  async function median(fn) {
    const xs = [];
    for (let i = 0; i < 5; i++) { const t = performance.now(); await fn(); xs.push(performance.now() - t); }
    xs.sort((a, b) => a - b); return xs[2];
  }
  const known = await median(() => pbkdf2Hash("guess", salt, 100000));
  const naiveMissing = await median(async () => { return; }); // naive: instant return for unknown user
  const defendedMissing = await median(() => pbkdf2Hash("guess", salt, 100000)); // fake_verify does the work anyway
  out.innerHTML =
    `<div><b>Naive server</b> (returns instantly for unknown users):<br>` +
    `known user, wrong password: ${known.toFixed(1)} ms · unknown user: ${naiveMissing.toFixed(2)} ms — ` +
    `<span class="bad">the gap enumerates valid accounts</span></div>` +
    `<div style="margin-top:8px"><b>Defended</b> (fake_verify burns the same time):<br>` +
    `known: ${known.toFixed(1)} ms · unknown: ${defendedMissing.toFixed(1)} ms — ` +
    `<span class="good">no timing oracle</span></div>`;
}

/* ------------------------------------------------------------------ */
/* 6. Authorization models: RBAC / ABAC / ReBAC / Cedar / Rego        */
/* ------------------------------------------------------------------ */

const policySubjects = {
  alice: { tenant: "blue", groups: ["platform"], admin: false },
  bob: { tenant: "blue", groups: [], admin: false },
  root: { tenant: "blue", groups: [], admin: true },
  carol: { tenant: "red", groups: [], admin: false },
  mallory: { tenant: "blue", groups: [], admin: false },
};
const policyResources = {
  budget: { tenant: "blue", owner: "bob", readerGroup: "eng", locked: false },
  locked: { tenant: "blue", owner: "bob", readerGroup: "eng", locked: true },
  "red-plan": { tenant: "red", owner: "carol", readerGroup: "eng", locked: false },
};
const policyGroupParents = { platform: ["eng"] };
const policyCases = {
  "nested-group-read": ["alice", "read", "budget"],
  "group-cannot-write": ["alice", "write", "budget"],
  "owner-write": ["bob", "write", "budget"],
  "explicit-deny-owner": ["bob", "read", "locked"],
  "tenant-admin": ["root", "write", "budget"],
  "tenant-boundary": ["root", "read", "red-plan"],
  "default-deny": ["mallory", "read", "budget"],
  "other-tenant-owner": ["carol", "write", "red-plan"],
};

function policyInGroup(subject, target, maxDepth) {
  const pending = subject.groups.map(group => [group, 0, new Set()]);
  while (pending.length) {
    const [group, depth, path] = pending.pop();
    if (path.has(group) || depth > maxDepth) continue;
    if (group === target) return true;
    const nextPath = new Set(path);
    nextPath.add(group);
    for (const parent of policyGroupParents[group] || []) {
      pending.push([parent, depth + 1, nextPath]);
    }
  }
  return false;
}

function policyGuard(subject, resource) {
  if (subject.tenant !== resource.tenant) return "tenant boundary";
  if (resource.locked) return "explicit deny: locked";
  return "";
}

function policyPermit(subjectId, action, resourceId) {
  const subject = policySubjects[subjectId];
  const resource = policyResources[resourceId];
  if (!["read", "write"].includes(action)) return "";
  if (subject.admin) return "tenant admin";
  if (resource.owner === subjectId) return "owner";
  if (action === "read" && policyInGroup(subject, resource.readerGroup, 25)) {
    return "platform → eng nested group";
  }
  return "";
}

function policyParityDemo() {
  const select = document.getElementById("policy-scenario");
  if (!select) return;
  const [subjectId, action, resourceId] = policyCases[select.value];
  const subject = policySubjects[subjectId];
  const resource = policyResources[resourceId];
  const guard = policyGuard(subject, resource);
  const permit = policyPermit(subjectId, action, resourceId);
  const allowed = !guard && Boolean(permit);
  const modelReasons = {
    RBAC: guard || (permit ? `materialized resource role: ${permit}` : "default deny"),
    ABAC: guard || (permit ? `deny-overrides attribute policy: ${permit}` : "default deny"),
    ReBAC: guard || (permit ? `relationship path: ${permit}` : "no relation path"),
    Cedar: guard
      ? `forbid overrides permit: ${guard}`
      : (permit ? `permit: ${permit}` : "default deny"),
    Rego: guard
      ? `deny; allow requires not deny: ${guard}`
      : (permit ? `permit and not deny: ${permit}` : "default allow := false"),
  };

  document.getElementById("policy-query").textContent =
    `check(subject=${subjectId}, action=${action}, resource=${resourceId})`;
  document.getElementById("policy-results").innerHTML =
    Object.entries(modelReasons).map(([model, reason]) =>
      `<tr><td><code>${model}</code></td>` +
      `<td><span class="${allowed ? "good" : "bad"}">${allowed ? "ALLOW" : "DENY"}</span></td>` +
      `<td>${reason}</td></tr>`
    ).join("");
}

// ReBAC mini-engine mirroring authlab.authz.rebac (this + computed + tuple_to_userset)
function rebacDemo() {
  const tuples = [
    "group:eng#member@user:alice",
    "group:eng#member@group:platform#member",
    "group:platform#member@user:carol",
    "folder:2024#viewer@group:eng#member",
    "document:budget#parent@folder:2024",
    "document:budget#owner@user:erin",
  ];
  const rewrites = {
    "folder:viewer": ["this", ["computed", "editor"]],
    "folder:editor": ["this", ["computed", "owner"]],
    "document:viewer": ["this", ["computed", "editor"], ["ttu", "parent", "viewer"]],
    "document:editor": ["this", ["computed", "owner"], ["ttu", "parent", "editor"]],
  };
  function typeof_(obj) { return obj.split(":")[0]; }
  function direct(obj, rel) {
    return tuples.filter(t => {
      const [o, rest] = t.split("#"); const [r] = rest.split("@");
      return o === obj && r === rel;
    }).map(t => t.split("@")[1]);
  }
  function check(obj, rel, user, seen) {
    seen = seen || new Set();
    const key = obj + "#" + rel + "@" + user;
    if (seen.has(key)) return false;
    seen.add(key);
    const rw = rewrites[typeof_(obj) + ":" + rel] || ["this"];
    for (const rule of rw) {
      if (rule === "this") {
        for (const u of direct(obj, rel)) {
          if (u === user) return true;
          if (u.indexOf("#") !== -1) {
            const [so, sr] = u.split("#");
            if (check(so, sr, user, seen)) return true;
          }
        }
      } else if (rule[0] === "computed") {
        if (check(obj, rule[1], user, seen)) return true;
      } else if (rule[0] === "ttu") {
        for (const p of direct(obj, rule[1])) {
          if (check(p.split("#")[0], rule[2], user, seen)) return true;
        }
      }
    }
    return false;
  }
  const obj = document.getElementById("rebac-obj").value;
  const rel = document.getElementById("rebac-rel").value;
  const user = document.getElementById("rebac-user").value.trim();
  const result = check(obj, rel, user);
  const out = document.getElementById("rebac-result");
  out.innerHTML = `check(<code>${obj}#${rel}@${user}</code>) = ` +
    `<span class="${result ? "good" : "bad"}">${result}</span>`;
  // explain path for a couple of known cases
  const why = {
    "user:alice": "alice ∈ group:eng → eng is a viewer of folder:2024 → budget's parent is folder:2024 → viewer inherited.",
    "user:carol": "carol ∈ group:platform ∈ group:eng (nested group) → same folder-inheritance path.",
    "user:erin": "erin owns document:budget → owner implies editor implies viewer.",
    "user:mallory": "mallory has no tuple and no group/folder path → denied.",
  };
  if (why[user]) out.innerHTML += `<div class="note">${why[user]}</div>`;
}

/* ------------------------------------------------------------------ */
/* 8. redirect_uri matching demo                                     */
/* ------------------------------------------------------------------ */

function checkRedirect() {
  const registered = "https://app.example.com/callback";
  const candidate = document.getElementById("redir-input").value.trim();
  const exact = candidate === registered;
  const prefix = candidate.startsWith(registered); // the WRONG way
  const out = document.getElementById("redir-result");
  out.innerHTML =
    `registered: <code>${registered}</code><br>` +
    `candidate: <code>${candidate || "(empty)"}</code><br>` +
    `<b>exact match</b> (authlab): <span class="${exact ? "good" : "bad"}">${exact ? "ALLOW" : "REJECT"}</span> · ` +
    `<b>startsWith</b> (naive): <span class="${prefix && !exact ? "bad" : ""}">${prefix ? "ALLOW" : "REJECT"}</span>` +
    (prefix && !exact ? `<div class="note bad">startsWith accepts this but exact-match rejects it. This gap is how <code>${registered}.attacker.net</code> or <code>${registered}/../open-redirect</code> steal the code.</div>` : "");
}

/* ------------------------------------------------------------------ */
/* tabs                                                               */
/* ------------------------------------------------------------------ */

function revealSelectedTab(button, smooth = true) {
  const tabs = button?.closest(".tabs");
  if (!tabs) return;
  const left = button.offsetLeft - (tabs.clientWidth - button.offsetWidth) / 2;
  tabs.scrollTo({ left: Math.max(0, left), behavior: smooth ? "smooth" : "auto" });
}

function showTab(id, btn, options = {}) {
  const panel = document.getElementById(id);
  if (!panel || !panel.classList.contains("tab-panel")) return;
  document.querySelectorAll(".tab-panel").forEach(p => {
    const active = p === panel;
    p.classList.toggle("active", active);
    p.hidden = !active;
  });
  const selected = btn || document.querySelector(`.tab-btn[data-tab-target="${id}"]`);
  document.querySelectorAll(".tab-btn").forEach(b => {
    const active = b === selected;
    b.classList.toggle("active", active);
    b.setAttribute("aria-selected", String(active));
    b.tabIndex = active ? 0 : -1;
  });
  revealSelectedTab(selected, options.scroll !== false);
  if (options.updateHash !== false && window.history?.replaceState) {
    window.history.replaceState(null, "", `#${id}`);
  }
  document.dispatchEvent(new CustomEvent("authlab:tabshown", { detail: { id } }));
  if (options.scroll !== false) window.scrollTo({ top: 0, behavior: "smooth" });
}

document.addEventListener("DOMContentLoaded", () => {
  const tabs = [...document.querySelectorAll(".tab-btn")];
  for (const tab of tabs) {
    tab.addEventListener("keydown", event => {
      const current = tabs.indexOf(tab);
      let next = null;
      if (event.key === "ArrowRight") next = (current + 1) % tabs.length;
      if (event.key === "ArrowLeft") next = (current - 1 + tabs.length) % tabs.length;
      if (event.key === "Home") next = 0;
      if (event.key === "End") next = tabs.length - 1;
      if (next === null) return;
      event.preventDefault();
      tabs[next].click();
      tabs[next].focus();
    });
  }
  const requested = window.location.hash.slice(1);
  const initial = document.getElementById(requested)?.classList.contains("tab-panel")
    ? requested
    : "t-start";
  showTab(initial, null, { scroll: false, updateHash: Boolean(requested) });
  window.addEventListener("hashchange", () => {
    const id = window.location.hash.slice(1);
    showTab(id, null, { scroll: false, updateHash: false });
  });
  window.addEventListener("resize", () => {
    revealSelectedTab(document.querySelector(".tab-btn.active"), false);
  });
  if (document.getElementById("jwt-input")) decodeJwt();
  if (document.getElementById("policy-scenario")) policyParityDemo();
  // report Web Crypto availability
  const badge = document.getElementById("crypto-badge");
  if (badge) badge.textContent = crypto && crypto.subtle ? "Web Crypto: available ✓" : "Web Crypto: unavailable (use https or localhost)";
});
