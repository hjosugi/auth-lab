"use strict";

const encoder = new TextEncoder();

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function decodeBase64Url(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function formatJsonPart(value) {
  const bytes = decodeBase64Url(value);
  return JSON.stringify(JSON.parse(new TextDecoder().decode(bytes)), null, 2);
}

const flowData = {
  oauth: {
    actors: ["Client", "Browser", "Authorization Server", "API"],
    steps: [
      [0, 2, "authorize + challenge", "stateはブラウザtransaction、PKCE challengeはcode交換をclient instanceへ束縛する。"],
      [2, 1, "authenticate + consent", "Authorization Serverだけがresource ownerの認証と同意を担当する。"],
      [1, 0, "code + state", "Clientはstateとexact redirect URIを検証してからcodeを扱う。"],
      [0, 2, "code + verifier", "秘密のverifierからS256 challengeを再計算し、code横取りを拒否する。"],
      [2, 0, "access + ID + refresh", "ID TokenはClient向け。Access TokenはAPI向け。audienceを混同しない。"],
      [0, 3, "access token", "APIはissuer、audience、expiry、token type、scopeを検証する。"]
    ]
  },
  saml: {
    actors: ["Browser", "Service Provider", "Identity Provider"],
    steps: [
      [0, 1, "protected page", "SPは一回性のrequest IDとRelayStateを生成する。"],
      [1, 2, "AuthnRequest", "IdPは信頼済みmetadataからSPとresponse先を特定する。"],
      [2, 0, "signed assertion", "Browserは運搬者であり、信頼の根ではない。"],
      [0, 1, "POST exact ACS", "署名対象Assertion、issuer、audience、ACS、request、時刻、replayを検証する。"]
    ]
  },
  kerberos: {
    actors: ["Client", "AS", "TGS", "Service"],
    steps: [
      [0, 1, "AS-REQ + pre-auth", "Clientはpassword由来keyの所持を証明する。password自体はserviceへ送らない。"],
      [1, 0, "TGT + session key", "TGTはTGSだけが開ける。client partはuser keyで保護される。"],
      [0, 2, "TGT + authenticator", "fresh timestampとnonceを持つauthenticatorでreplayを防ぐ。"],
      [2, 0, "service ticket", "service principal専用keyで暗号化されたticketを受け取る。"],
      [0, 3, "ticket + authenticator", "Serviceはticketの宛先、期限、authenticator、replay cacheを検証する。"]
    ]
  },
  webauthn: {
    actors: ["Browser", "Relying Party", "Authenticator"],
    steps: [
      [1, 0, "challenge + RP ID", "高entropyのchallengeがceremonyを一回性にする。"],
      [0, 2, "origin-bound request", "Browserが現在のoriginとRP contextをAuthenticatorへ渡す。"],
      [2, 0, "signed assertion", "User Presence / Verification後、秘密鍵でauthenticatorDataを署名する。"],
      [0, 1, "clientData + assertion", "RPはchallenge、origin、rpIdHash、flags、署名、counterを検証する。"]
    ]
  }
};

let flowStep = 0;
const flowSelect = document.querySelector("#flow-select");
const flowCanvas = document.querySelector("#flow-canvas");
const flowCount = document.querySelector("#flow-count");
const flowDetail = document.querySelector("#flow-detail");
const flowPrev = document.querySelector("#flow-prev");
const flowNext = document.querySelector("#flow-next");

function renderFlow() {
  const flow = flowData[flowSelect.value];
  flowStep = Math.max(0, Math.min(flowStep, flow.steps.length - 1));
  const [from, to, message, detail] = flow.steps[flowStep];
  const minimum = Math.min(from, to);
  const distance = Math.abs(from - to);
  const left = (minimum + 0.5) * 100 / flow.actors.length;
  const width = distance * 100 / flow.actors.length;
  const direction = to > from ? "forward" : "backward";
  const actors = flow.actors.map((actor) => (
    `<div class="actor"><span class="actor-box">${actor}</span></div>`
  )).join("");
  flowCanvas.innerHTML = `
    <div class="flow-diagram" style="--actors:${flow.actors.length}">
      ${actors}
      <span class="message-label" style="left:${left + width / 2}%">${message}</span>
      <span class="message-line ${direction}" style="left:${left}%;width:${width}%"></span>
    </div>`;
  flowCount.textContent = `${String(flowStep + 1).padStart(2, "0")} / ${String(flow.steps.length).padStart(2, "0")}`;
  flowDetail.textContent = detail;
  flowPrev.disabled = flowStep === 0;
  flowNext.disabled = flowStep === flow.steps.length - 1;
}

flowSelect.addEventListener("change", () => { flowStep = 0; renderFlow(); });
flowPrev.addEventListener("click", () => { flowStep -= 1; renderFlow(); });
flowNext.addEventListener("click", () => { flowStep += 1; renderFlow(); });

const pkceVerifier = document.querySelector("#pkce-verifier");
const pkceChallenge = document.querySelector("#pkce-challenge");
const pkceStatus = document.querySelector("#pkce-status");

function randomVerifier() {
  const bytes = crypto.getRandomValues(new Uint8Array(64));
  return base64Url(bytes);
}

async function calculatePkce() {
  const verifier = pkceVerifier.value.trim();
  if (verifier.length < 43 || verifier.length > 128 || !/^[A-Za-z0-9._~-]+$/u.test(verifier)) {
    pkceChallenge.textContent = "";
    pkceStatus.className = "status error";
    pkceStatus.textContent = "verifierは43〜128文字のunreserved文字にしてください。";
    return;
  }
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(verifier));
  pkceChallenge.textContent = base64Url(new Uint8Array(digest));
  pkceStatus.className = "status ok";
  pkceStatus.textContent = `✓ SHA-256 → base64url（${verifier.length}文字のverifier）`;
}

document.querySelector("#pkce-generate").addEventListener("click", () => {
  pkceVerifier.value = randomVerifier();
  calculatePkce();
});
document.querySelector("#pkce-calculate").addEventListener("click", calculatePkce);

const sampleHeader = base64Url(encoder.encode(JSON.stringify({ alg: "RS256", kid: "lab-1", typ: "JWT" })));
const samplePayload = base64Url(encoder.encode(JSON.stringify({
  iss: "https://issuer.example",
  sub: "alice",
  aud: "resource-api",
  exp: 1893456000,
  scope: "read"
})));
document.querySelector("#jwt-input").value = `${sampleHeader}.${samplePayload}.signature-not-verified`;

document.querySelector("#jwt-decode").addEventListener("click", () => {
  const [header, payload] = document.querySelector("#jwt-input").value.trim().split(".");
  try {
    if (!header || !payload) throw new Error("JWT must have header and payload");
    document.querySelector("#jwt-header").textContent = formatJsonPart(header);
    document.querySelector("#jwt-payload").textContent = formatJsonPart(payload);
  } catch (error) {
    document.querySelector("#jwt-header").textContent = "Invalid compact JWT";
    document.querySelector("#jwt-payload").textContent = error instanceof Error ? error.message : "Decode error";
  }
});

function decodeBase32(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = value.toUpperCase().replaceAll("=", "").replace(/\s+/gu, "");
  if (!normalized || [...normalized].some((character) => !alphabet.includes(character))) {
    throw new Error("Base32 secretが不正です");
  }
  let bits = "";
  for (const character of normalized) bits += alphabet.indexOf(character).toString(2).padStart(5, "0");
  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }
  return new Uint8Array(bytes);
}

async function calculateTotp() {
  const output = document.querySelector("#totp-code");
  const status = document.querySelector("#totp-status");
  try {
    const secret = decodeBase32(document.querySelector("#totp-secret").value);
    const unixTime = Number.parseInt(document.querySelector("#totp-time").value, 10);
    if (!Number.isSafeInteger(unixTime) || unixTime < 0) throw new Error("Unix timeが不正です");
    const counter = Math.floor(unixTime / 30);
    const movingFactor = new Uint8Array(8);
    new DataView(movingFactor.buffer).setBigUint64(0, BigInt(counter));
    const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, movingFactor));
    const offset = mac[mac.length - 1] & 0x0f;
    const binary = ((mac[offset] & 0x7f) << 24)
      | (mac[offset + 1] << 16)
      | (mac[offset + 2] << 8)
      | mac[offset + 3];
    const code = String(binary % 1_000_000).padStart(6, "0");
    output.textContent = code.split("").join(" ");
    status.className = "status ok";
    status.textContent = `✓ counter = floor(${unixTime} / 30) = ${counter}`;
  } catch (error) {
    output.textContent = "— — — — — —";
    status.className = "status error";
    status.textContent = error instanceof Error ? error.message : "TOTP計算エラー";
  }
}

document.querySelector("#totp-now").addEventListener("click", () => {
  document.querySelector("#totp-time").value = String(Math.floor(Date.now() / 1000));
  calculateTotp();
});
document.querySelector("#totp-calculate").addEventListener("click", calculateTotp);

const authorizationData = {
  alice: { role: "editor", team: "blue", relations: ["alice", "team:blue"] },
  bob: { role: "viewer", team: "red", relations: ["bob"] }
};

function evaluateAuthorization() {
  const userName = document.querySelector("#authz-user").value;
  const action = document.querySelector("#authz-action").value;
  const owner = document.querySelector("#authz-owner").value;
  const locked = document.querySelector("#authz-locked").checked;
  const user = authorizationData[userName];
  const rbac = action === "read" || user.role === "editor";
  const abac = !locked && (userName === owner || user.team === authorizationData[owner].team);
  const rebac = user.relations.includes(owner) || user.relations.includes(`team:${authorizationData[owner].team}`);
  const decisions = [
    ["RBAC", rbac, rbac ? `${user.role} has ${action}` : `${user.role} lacks ${action}`],
    ["ABAC", abac, locked ? "explicit deny: resource locked" : "owner/team attributes"],
    ["ReBAC", rebac, rebac ? "direct or team relationship" : "no relationship path"]
  ];
  document.querySelector("#authz-results").innerHTML = decisions.map(([model, allow, reason]) => `
    <div class="decision">
      <b>${model}</b>
      <strong class="${allow ? "allow" : "deny"}">${allow ? "ALLOW" : "DENY"}</strong>
      <span>${reason}</span>
    </div>`).join("");
}

document.querySelector("#authz-evaluate").addEventListener("click", evaluateAuthorization);

pkceVerifier.value = randomVerifier();
calculatePkce();
document.querySelector("#jwt-decode").click();
calculateTotp();
evaluateAuthorization();
renderFlow();
