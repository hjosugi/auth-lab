"use strict";

(function publishWebAuthnLab(global) {
  const textDecoder = new TextDecoder();
  const textEncoder = new TextEncoder();
  const FLAG_UP = 0x01;
  const FLAG_UV = 0x04;
  const FLAG_BE = 0x08;
  const FLAG_BS = 0x10;
  const FLAG_AT = 0x40;

  function bytes(value) {
    return value instanceof Uint8Array ? value : new Uint8Array(value);
  }

  function base64urlEncode(value) {
    let binary = "";
    for (const octet of bytes(value)) binary += String.fromCharCode(octet);
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  }

  function base64urlDecode(value) {
    const padded = value.replaceAll("-", "+").replaceAll("_", "/")
      + "=".repeat((4 - (value.length % 4)) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  function equalBytes(left, right) {
    const first = bytes(left);
    const second = bytes(right);
    if (first.length !== second.length) return false;
    let difference = 0;
    for (let index = 0; index < first.length; index += 1) {
      difference |= first[index] ^ second[index];
    }
    return difference === 0;
  }

  function readCborLength(data, offset, additional) {
    if (additional < 24) return { value: additional, offset };
    const sizes = { 24: 1, 25: 2, 26: 4, 27: 8 };
    const size = sizes[additional];
    if (!size || offset + size > data.length) throw new Error("Unsupported or truncated CBOR length");
    let value = 0;
    for (let index = 0; index < size; index += 1) value = value * 256 + data[offset + index];
    if (!Number.isSafeInteger(value)) throw new Error("CBOR integer exceeds JavaScript safe range");
    return { value, offset: offset + size };
  }

  function decodeCborAt(input, start = 0) {
    const data = bytes(input);
    if (start >= data.length) throw new Error("Truncated CBOR value");
    const initial = data[start];
    const major = initial >> 5;
    const additional = initial & 0x1f;
    const length = readCborLength(data, start + 1, additional);
    let offset = length.offset;

    if (major === 0) return { value: length.value, offset };
    if (major === 1) return { value: -1 - length.value, offset };
    if (major === 2 || major === 3) {
      const end = offset + length.value;
      if (end > data.length) throw new Error("Truncated CBOR string");
      const raw = data.slice(offset, end);
      return { value: major === 2 ? raw : textDecoder.decode(raw), offset: end };
    }
    if (major === 4) {
      const value = [];
      for (let index = 0; index < length.value; index += 1) {
        const item = decodeCborAt(data, offset);
        value.push(item.value);
        offset = item.offset;
      }
      return { value, offset };
    }
    if (major === 5) {
      const value = new Map();
      for (let index = 0; index < length.value; index += 1) {
        const key = decodeCborAt(data, offset);
        const item = decodeCborAt(data, key.offset);
        value.set(key.value, item.value);
        offset = item.offset;
      }
      return { value, offset };
    }
    if (major === 7 && additional === 20) return { value: false, offset };
    if (major === 7 && additional === 21) return { value: true, offset };
    if (major === 7 && (additional === 22 || additional === 23)) return { value: null, offset };
    throw new Error(`Unsupported CBOR major type ${major}`);
  }

  function decodeCbor(input) {
    return decodeCborAt(input).value;
  }

  function parseAuthenticatorData(input) {
    const data = bytes(input);
    if (data.length < 37) throw new Error("Authenticator data is shorter than 37 bytes");
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const flagsByte = data[32];
    if ((flagsByte & FLAG_BS) && !(flagsByte & FLAG_BE)) {
      throw new Error("Backup state flag is set without backup eligibility");
    }
    const result = {
      rpIdHash: data.slice(0, 32),
      flagsByte,
      userPresent: Boolean(flagsByte & FLAG_UP),
      userVerified: Boolean(flagsByte & FLAG_UV),
      backupEligible: Boolean(flagsByte & FLAG_BE),
      backupState: Boolean(flagsByte & FLAG_BS),
      signCount: view.getUint32(33, false),
      credentialId: null,
      credentialPublicKey: null,
    };
    if (!(flagsByte & FLAG_AT)) return result;

    let offset = 37 + 16;
    if (offset + 2 > data.length) throw new Error("Truncated attested credential data");
    const credentialIdLength = view.getUint16(offset, false);
    offset += 2;
    if (offset + credentialIdLength > data.length) throw new Error("Truncated credential ID");
    result.credentialId = data.slice(offset, offset + credentialIdLength);
    offset += credentialIdLength;
    const publicKey = decodeCborAt(data, offset);
    result.credentialPublicKey = data.slice(offset, publicKey.offset);
    result.coseKey = publicKey.value;
    return result;
  }

  function parseAttestationObject(input) {
    const value = decodeCbor(input);
    if (!(value instanceof Map) || !(value.get("authData") instanceof Uint8Array)) {
      throw new Error("Attestation object lacks authenticator data");
    }
    return {
      format: value.get("fmt"),
      statement: value.get("attStmt"),
      authenticator: parseAuthenticatorData(value.get("authData")),
    };
  }

  function parseClientData(input) {
    return JSON.parse(textDecoder.decode(bytes(input)));
  }

  function validateClientData(clientData, expected) {
    if (clientData.type !== expected.type) {
      throw new Error(`Unexpected ceremony type: ${clientData.type}`);
    }
    if (clientData.challenge !== base64urlEncode(expected.challenge)) {
      throw new Error("Challenge binding failed");
    }
    if (clientData.origin !== expected.origin) {
      throw new Error(`Origin binding failed: expected ${expected.origin}, received ${clientData.origin}`);
    }
    if (clientData.crossOrigin === true) throw new Error("Cross-origin ceremony is not allowed in this lab");
  }

  function coseEc2ToJwk(coseKey) {
    if (!(coseKey instanceof Map) || coseKey.get(1) !== 2 || coseKey.get(3) !== -7) {
      throw new Error("Only ES256 EC2 credential keys are supported");
    }
    const x = coseKey.get(-2);
    const y = coseKey.get(-3);
    if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) {
      throw new Error("COSE EC2 key is missing coordinates");
    }
    return {
      kty: "EC",
      crv: "P-256",
      x: base64urlEncode(x),
      y: base64urlEncode(y),
      ext: true,
      key_ops: ["verify"],
    };
  }

  function derEcdsaToRaw(input, coordinateSize = 32) {
    const data = bytes(input);
    let offset = 0;
    function readLength() {
      const first = data[offset++];
      if (first < 0x80) return first;
      const octets = first & 0x7f;
      if (octets < 1 || octets > 2 || offset + octets > data.length) {
        throw new Error("Invalid DER length");
      }
      let length = 0;
      for (let index = 0; index < octets; index += 1) length = length * 256 + data[offset++];
      return length;
    }
    if (data[offset++] !== 0x30) throw new Error("ECDSA signature is not a DER sequence");
    const sequenceLength = readLength();
    if (offset + sequenceLength !== data.length) throw new Error("ECDSA DER sequence length mismatch");
    const output = new Uint8Array(coordinateSize * 2);
    for (let part = 0; part < 2; part += 1) {
      if (data[offset++] !== 0x02) throw new Error("ECDSA DER sequence lacks an integer");
      const integerLength = readLength();
      const integer = data.slice(offset, offset + integerLength);
      offset += integerLength;
      const unsigned = integer[0] === 0 ? integer.slice(1) : integer;
      if (unsigned.length > coordinateSize) throw new Error("ECDSA coordinate is too large");
      output.set(unsigned, (part + 1) * coordinateSize - unsigned.length);
    }
    return output;
  }

  function concatBytes(...parts) {
    const total = parts.reduce((length, part) => length + bytes(part).length, 0);
    const output = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
      const value = bytes(part);
      output.set(value, offset);
      offset += value.length;
    }
    return output;
  }

  function createWebAuthnLab(environment = global) {
    const navigatorObject = environment.navigator;
    const cryptoObject = environment.crypto;
    const locationObject = environment.location;
    if (!navigatorObject?.credentials || !cryptoObject?.subtle || !locationObject) {
      throw new Error("WebAuthn requires navigator.credentials and Web Crypto on HTTPS or localhost");
    }

    const credentials = new Map();
    const rpId = locationObject.hostname;
    const origin = locationObject.origin;

    function challenge() {
      return cryptoObject.getRandomValues(new Uint8Array(32));
    }

    async function validateRpId(authenticator) {
      const expected = new Uint8Array(await cryptoObject.subtle.digest("SHA-256", textEncoder.encode(rpId)));
      if (!equalBytes(authenticator.rpIdHash, expected)) throw new Error("RP ID hash binding failed");
    }

    async function register(options = {}) {
      const residentKey = options.residentKey || "discouraged";
      const userVerification = options.userVerification || "preferred";
      const attestation = options.attestation || "none";
      const ceremonyChallenge = challenge();
      const userId = challenge().slice(0, 16);
      const credential = await navigatorObject.credentials.create({
        publicKey: {
          rp: { id: rpId, name: "auth-lab teaching RP" },
          user: {
            id: userId,
            name: `learner-${base64urlEncode(userId).slice(0, 8)}`,
            displayName: "auth-lab learner",
          },
          challenge: ceremonyChallenge,
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          authenticatorSelection: {
            residentKey,
            requireResidentKey: residentKey === "required",
            userVerification,
          },
          timeout: 15_000,
          attestation,
        },
      });
      const clientData = parseClientData(credential.response.clientDataJSON);
      validateClientData(clientData, {
        type: "webauthn.create",
        challenge: ceremonyChallenge,
        origin,
      });
      const attestationData = parseAttestationObject(credential.response.attestationObject);
      await validateRpId(attestationData.authenticator);
      if (!attestationData.authenticator.userPresent) throw new Error("User presence flag is missing");
      if (userVerification === "required" && !attestationData.authenticator.userVerified) {
        throw new Error("User verification flag is missing");
      }
      const id = base64urlEncode(credential.rawId);
      if (attestationData.authenticator.credentialId
          && !equalBytes(attestationData.authenticator.credentialId, credential.rawId)) {
        throw new Error("Credential ID binding failed");
      }
      const publicKey = await cryptoObject.subtle.importKey(
        "jwk",
        coseEc2ToJwk(attestationData.authenticator.coseKey),
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
      credentials.set(id, {
        id,
        publicKey,
        signCount: attestationData.authenticator.signCount,
        resident: residentKey === "required",
        userHandle: base64urlEncode(userId),
      });
      return {
        id,
        resident: residentKey === "required",
        userVerified: attestationData.authenticator.userVerified,
        backupEligible: attestationData.authenticator.backupEligible,
        backupState: attestationData.authenticator.backupState,
        signCount: attestationData.authenticator.signCount,
        attestationFormat: attestationData.format,
      };
    }

    async function authenticate(options = {}) {
      const discoverable = Boolean(options.discoverable);
      const userVerification = options.userVerification || "preferred";
      const ceremonyChallenge = challenge();
      const request = {
        challenge: ceremonyChallenge,
        rpId,
        userVerification,
        timeout: 15_000,
      };
      if (!discoverable) {
        const candidate = options.credentialId || [...credentials.keys()].at(-1);
        if (!candidate || !credentials.has(candidate)) throw new Error("Register a credential first");
        request.allowCredentials = [{
          type: "public-key",
          id: base64urlDecode(candidate),
          transports: ["internal", "usb", "nfc", "ble", "hybrid"],
        }];
      }
      const assertion = await navigatorObject.credentials.get({ publicKey: request });
      const id = base64urlEncode(assertion.rawId);
      const stored = credentials.get(id);
      if (!stored) throw new Error("The teaching RP does not know this credential");
      const clientData = parseClientData(assertion.response.clientDataJSON);
      validateClientData(clientData, {
        type: "webauthn.get",
        challenge: ceremonyChallenge,
        origin,
      });
      const authenticator = parseAuthenticatorData(assertion.response.authenticatorData);
      await validateRpId(authenticator);
      if (!authenticator.userPresent) throw new Error("User presence flag is missing");
      if (userVerification === "required" && !authenticator.userVerified) {
        throw new Error("User verification flag is missing");
      }
      const clientDataHash = await cryptoObject.subtle.digest(
        "SHA-256",
        assertion.response.clientDataJSON,
      );
      const signed = concatBytes(assertion.response.authenticatorData, clientDataHash);
      const signature = derEcdsaToRaw(assertion.response.signature);
      const verified = await cryptoObject.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        stored.publicKey,
        signature,
        signed,
      );
      if (!verified) throw new Error("Assertion signature verification failed");
      const cloneSuspected = stored.signCount > 0
        && authenticator.signCount > 0
        && authenticator.signCount <= stored.signCount;
      stored.signCount = Math.max(stored.signCount, authenticator.signCount);
      return {
        id,
        discoverable,
        verified,
        cloneSuspected,
        userVerified: authenticator.userVerified,
        backupEligible: authenticator.backupEligible,
        backupState: authenticator.backupState,
        signCount: authenticator.signCount,
        userHandle: assertion.response.userHandle
          ? base64urlEncode(assertion.response.userHandle)
          : null,
      };
    }

    async function probeOriginMismatch() {
      const ceremonyChallenge = challenge();
      const clientData = {
        type: "webauthn.get",
        challenge: base64urlEncode(ceremonyChallenge),
        origin,
      };
      try {
        validateClientData(clientData, {
          type: "webauthn.get",
          challenge: ceremonyChallenge,
          origin: "https://lookalike.invalid",
        });
      } catch (error) {
        return { rejected: true, name: error.name, message: error.message };
      }
      throw new Error("Origin mismatch was unexpectedly accepted");
    }

    async function probeRpIdMismatch() {
      try {
        await navigatorObject.credentials.get({
          publicKey: {
            challenge: challenge(),
            rpId: "example.com",
            userVerification: "discouraged",
            timeout: 2_000,
          },
        });
      } catch (error) {
        return { rejected: true, name: error.name, message: error.message };
      }
      throw new Error("RP ID mismatch was unexpectedly accepted");
    }

    function reset() {
      credentials.clear();
    }

    return {
      authenticate,
      credentialIds: () => [...credentials.keys()],
      probeOriginMismatch,
      probeRpIdMismatch,
      register,
      reset,
    };
  }

  function installWebAuthnLab(documentObject = global.document) {
    const status = documentObject?.getElementById("webauthn-status");
    if (!status) return null;
    let lab;
    try {
      lab = createWebAuthnLab(global);
    } catch (error) {
      status.textContent = error.message;
      status.className = "out bad";
      return null;
    }
    const residentKey = documentObject.getElementById("webauthn-resident-key");
    const userVerification = documentObject.getElementById("webauthn-user-verification");
    const attestation = documentObject.getElementById("webauthn-attestation");
    const run = (label, action) => async () => {
      status.className = "out";
      status.textContent = `${label} を実行中… ブラウザの認証器 UI を完了してください。`;
      try {
        const result = await action();
        status.className = "out good";
        status.textContent = `${label}: 成功\n${JSON.stringify(result, null, 2)}`;
      } catch (error) {
        status.className = "out bad";
        status.textContent = `${label}: 拒否\n${error.name}: ${error.message}`;
      }
    };
    documentObject.getElementById("webauthn-register").addEventListener("click", run(
      "登録",
      () => lab.register({
        residentKey: residentKey.value,
        userVerification: userVerification.value,
        attestation: attestation.value,
      }),
    ));
    documentObject.getElementById("webauthn-authenticate").addEventListener("click", run(
      "allowCredentials 認証",
      () => lab.authenticate({ userVerification: userVerification.value }),
    ));
    documentObject.getElementById("webauthn-discoverable").addEventListener("click", run(
      "discoverable 認証",
      () => lab.authenticate({ discoverable: true, userVerification: userVerification.value }),
    ));
    documentObject.getElementById("webauthn-origin-negative").addEventListener(
      "click",
      run("origin 不一致テスト", () => lab.probeOriginMismatch()),
    );
    documentObject.getElementById("webauthn-rpid-negative").addEventListener(
      "click",
      run("RP ID 不一致テスト", () => lab.probeRpIdMismatch()),
    );
    documentObject.getElementById("webauthn-reset").addEventListener("click", () => {
      lab.reset();
      status.className = "out";
      status.textContent = "教材 RP のメモリ内 credential を消去しました。認証器側の鍵はブラウザ設定から管理してください。";
    });
    return lab;
  }

  const api = {
    base64urlDecode,
    base64urlEncode,
    coseEc2ToJwk,
    createWebAuthnLab,
    decodeCbor,
    derEcdsaToRaw,
    installWebAuthnLab,
    parseAttestationObject,
    parseAuthenticatorData,
    parseClientData,
    validateClientData,
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.AuthLabPasskeys = api;
  if (global.document) {
    global.document.addEventListener("DOMContentLoaded", () => {
      api.lab = installWebAuthnLab(global.document);
    });
  }
}(typeof globalThis === "undefined" ? window : globalThis));
