#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { access, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const docs = path.join(root, "docs");
const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
  ".svg": "image/svg+xml",
};

async function findBrowser() {
  const names = [
    process.env.AUTHLAB_BROWSER,
    "google-chrome-stable",
    "google-chrome",
    "chromium",
    "chromium-browser",
    "brave-browser",
    "brave",
  ].filter(Boolean);
  const directories = (process.env.PATH || "").split(path.delimiter);
  for (const name of names) {
    const candidates = path.isAbsolute(name)
      ? [name]
      : directories.map((directory) => path.join(directory, name));
    for (const candidate of candidates) {
      try {
        await access(candidate);
        return candidate;
      } catch {
        // Continue to the next installed browser candidate.
      }
    }
  }
  throw new Error("Chrome, Chromium, or Brave is required for the native WebAuthn E2E");
}

function startStaticServer() {
  const server = http.createServer(async (request, response) => {
    try {
      const requestPath = new URL(request.url, "http://localhost").pathname;
      const relative = requestPath === "/" ? "index.html" : requestPath.slice(1);
      const filename = path.resolve(docs, relative);
      if (filename !== docs && !filename.startsWith(`${docs}${path.sep}`)) {
        response.writeHead(403).end("forbidden");
        return;
      }
      const fileStat = await stat(filename);
      const resolved = fileStat.isDirectory() ? path.join(filename, "index.html") : filename;
      const body = await readFile(resolved);
      response.writeHead(200, {
        "content-type": contentTypes[path.extname(resolved)] || "application/octet-stream",
        "cache-control": "no-store",
      });
      response.end(body);
    } catch {
      response.writeHead(404).end("not found");
    }
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, origin: `http://localhost:${port}` });
    });
  });
}

function launchBrowser(executable, profile) {
  const browser = spawn(executable, [
    "--headless=new",
    "--no-sandbox",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--no-first-run",
    "--no-default-browser-check",
    "--remote-debugging-port=0",
    `--user-data-dir=${profile}`,
    "about:blank",
  ], { stdio: ["ignore", "ignore", "pipe"] });
  return new Promise((resolve, reject) => {
    let stderr = "";
    const timeout = setTimeout(() => {
      browser.kill("SIGKILL");
      reject(new Error(`Browser did not expose DevTools in time:\n${stderr}`));
    }, 15_000);
    browser.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    browser.once("exit", (code) => {
      clearTimeout(timeout);
      reject(new Error(`Browser exited before DevTools was ready (${code}):\n${stderr}`));
    });
    browser.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
      const match = stderr.match(/DevTools listening on (ws:\/\/[^\s]+)/u);
      if (match) {
        clearTimeout(timeout);
        resolve({ browser, webSocketUrl: match[1] });
      }
    });
  });
}

class DevTools {
  constructor(url) {
    this.socket = new WebSocket(url);
    this.nextId = 1;
    this.pending = new Map();
    this.socket.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      if (!message.id) return;
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(`${pending.method}: ${message.error.message}`));
      else pending.resolve(message.result);
    });
  }

  async connect() {
    if (this.socket.readyState === WebSocket.OPEN) return;
    await new Promise((resolve, reject) => {
      this.socket.addEventListener("open", resolve, { once: true });
      this.socket.addEventListener("error", reject, { once: true });
    });
  }

  command(method, params = {}, sessionId = undefined) {
    const id = this.nextId++;
    const message = { id, method, params };
    if (sessionId) message.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`${method} timed out`));
      }, 20_000);
      this.pending.set(id, {
        method,
        resolve: (result) => {
          clearTimeout(timer);
          resolve(result);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      });
      this.socket.send(JSON.stringify(message));
    });
  }

  close() {
    this.socket.close();
  }
}

async function waitUntilReady(devtools, sessionId) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const result = await devtools.command("Runtime.evaluate", {
      expression: "document.readyState === 'complete' && Boolean(window.AuthLabPasskeys?.lab)",
      returnByValue: true,
    }, sessionId);
    if (result.result.value === true) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("Native WebAuthn lab did not initialize");
}

async function evaluate(devtools, sessionId, expression) {
  const result = await devtools.command("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  }, sessionId);
  if (result.exceptionDetails) {
    throw new Error(result.exceptionDetails.exception?.description
      || result.exceptionDetails.text
      || "Runtime evaluation failed");
  }
  return result.result.value;
}

async function stopBrowser(browser) {
  if (!browser || browser.exitCode !== null) return;
  await new Promise((resolve) => {
    const force = setTimeout(() => browser.kill("SIGKILL"), 5_000);
    browser.once("exit", () => {
      clearTimeout(force);
      resolve();
    });
    browser.kill("SIGTERM");
  });
}

async function main() {
  const executable = await findBrowser();
  const profile = await mkdtemp(path.join(os.tmpdir(), "auth-lab-webauthn-"));
  const { server, origin } = await startStaticServer();
  let browser;
  let devtools;
  try {
    const launched = await launchBrowser(executable, profile);
    browser = launched.browser;
    devtools = new DevTools(launched.webSocketUrl);
    await devtools.connect();
    const { targetId } = await devtools.command("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await devtools.command("Target.attachToTarget", {
      targetId,
      flatten: true,
    });
    await devtools.command("Page.enable", {}, sessionId);
    await devtools.command("Runtime.enable", {}, sessionId);
    await devtools.command("WebAuthn.enable", {}, sessionId);
    const { authenticatorId } = await devtools.command("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        ctap2Version: "ctap2_1",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        hasLargeBlob: true,
        automaticPresenceSimulation: true,
        isUserVerified: true,
        defaultBackupEligibility: true,
        defaultBackupState: true,
      },
    }, sessionId);
    await devtools.command("Page.navigate", { url: `${origin}/index.html` }, sessionId);
    await waitUntilReady(devtools, sessionId);

    const nonresident = await evaluate(
      devtools,
      sessionId,
      "AuthLabPasskeys.lab.register({residentKey:'discouraged',userVerification:'preferred'})",
    );
    assert.equal(nonresident.resident, false);
    assert.equal(nonresident.backupEligible, true);
    assert.equal(nonresident.backupState, true);
    const allowed = await evaluate(
      devtools,
      sessionId,
      "AuthLabPasskeys.lab.authenticate({userVerification:'preferred'})",
    );
    assert.equal(allowed.verified, true);
    assert.equal(allowed.discoverable, false);

    const resident = await evaluate(
      devtools,
      sessionId,
      "AuthLabPasskeys.lab.register({residentKey:'required',userVerification:'required'})",
    );
    assert.equal(resident.resident, true);
    assert.equal(resident.userVerified, true);
    const stored = await devtools.command(
      "WebAuthn.getCredentials",
      { authenticatorId },
      sessionId,
    );
    assert.ok(stored.credentials.some((credential) => credential.isResidentCredential === true));
    assert.ok(stored.credentials.some((credential) => credential.isResidentCredential === false));

    const discoverable = await evaluate(
      devtools,
      sessionId,
      "AuthLabPasskeys.lab.authenticate({discoverable:true,userVerification:'required'})",
    );
    assert.equal(discoverable.verified, true);
    assert.equal(discoverable.discoverable, true);
    assert.ok(discoverable.userHandle);

    await devtools.command("WebAuthn.setUserVerified", {
      authenticatorId,
      isUserVerified: false,
    }, sessionId);
    const uvRejection = await evaluate(devtools, sessionId, `(async () => {
      try {
        await AuthLabPasskeys.lab.authenticate({discoverable:true,userVerification:'required'});
        return {rejected:false};
      } catch (error) {
        return {rejected:true,name:error.name,message:error.message};
      }
    })()`);
    assert.equal(uvRejection.rejected, true);
    await devtools.command("WebAuthn.setUserVerified", {
      authenticatorId,
      isUserVerified: true,
    }, sessionId);

    const originRejection = await evaluate(
      devtools,
      sessionId,
      "AuthLabPasskeys.lab.probeOriginMismatch()",
    );
    assert.equal(originRejection.rejected, true);
    assert.match(originRejection.message, /Origin binding failed/u);
    const rpIdRejection = await evaluate(
      devtools,
      sessionId,
      "AuthLabPasskeys.lab.probeRpIdMismatch()",
    );
    assert.equal(rpIdRejection.rejected, true);
    assert.match(rpIdRejection.name, /SecurityError|NotAllowedError/u);

    console.log(JSON.stringify({
      browser: executable,
      origin,
      ceremonies: ["registration", "allowCredentials", "discoverable"],
      negativeTests: ["user verification", "origin", "RP ID"],
      virtualCredentials: stored.credentials.length,
    }));
  } finally {
    devtools?.close();
    await stopBrowser(browser);
    await new Promise((resolve) => server.close(resolve));
    await rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

await main();
