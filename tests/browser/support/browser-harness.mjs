import { spawn } from "node:child_process";
import { access, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const docs = path.join(root, "docs");
const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
  ".svg": "image/svg+xml",
  ".wasm": "application/wasm",
  ".zip": "application/zip",
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
  throw new Error("Chrome, Chromium, or Brave is required for browser E2E");
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

  command(method, params = {}, sessionId = undefined, timeoutMs = 60_000) {
    const id = this.nextId++;
    const message = { id, method, params };
    if (sessionId) message.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`${method} timed out`));
      }, timeoutMs);
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

export async function evaluate(session, expression, timeoutMs = 60_000) {
  const result = await session.devtools.command("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  }, session.sessionId, timeoutMs);
  if (result.exceptionDetails) {
    throw new Error(result.exceptionDetails.exception?.description
      || result.exceptionDetails.text
      || "Runtime evaluation failed");
  }
  return result.result.value;
}

export async function waitForExpression(session, expression, options = {}) {
  const attempts = options.attempts || 100;
  const intervalMs = options.intervalMs || 50;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (await evaluate(session, `Boolean(${expression})`)) return;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(options.message || `Browser condition did not become true: ${expression}`);
}

export async function navigate(session, pathname = "/index.html") {
  await session.devtools.command(
    "Page.navigate",
    { url: `${session.origin}${pathname}` },
    session.sessionId,
  );
  await waitForExpression(session, "document.readyState === 'complete'");
}

export async function createBrowserSession(profilePrefix = "auth-lab-browser-") {
  const executable = await findBrowser();
  const profile = await mkdtemp(path.join(os.tmpdir(), profilePrefix));
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
    return {
      browser,
      devtools,
      executable,
      origin,
      profile,
      server,
      sessionId,
      async close() {
        devtools.close();
        await stopBrowser(browser);
        await new Promise((resolve) => server.close(resolve));
        await rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      },
    };
  } catch (error) {
    devtools?.close();
    await stopBrowser(browser);
    await new Promise((resolve) => server.close(resolve));
    await rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    throw error;
  }
}
