"use strict";

import { loadPyodide } from "https://cdn.jsdelivr.net/pyodide/v314.0.2/full/pyodide.mjs";
import "./pyodide-policy.js";

const PYODIDE_VERSION = "314.0.2";
const PYODIDE_INDEX_URL = `https://cdn.jsdelivr.net/pyodide/v${PYODIDE_VERSION}/full/`;
const BUNDLE_URL = "authlab-pyodide.zip";
let runtimePromise = null;

function initializeExecutor(pyodide) {
  pyodide.runPython(`
import contextlib
import io
import traceback

def _authlab_execute(source):
    output = io.StringIO()
    try:
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            exec(compile(source, "<auth-lab-pyodide>", "exec"), globals(), globals())
    except BaseException:
        traceback.print_exc(file=output)
    return output.getvalue()
`);
}

function detectPasswordBackend(pyodide) {
  pyodide.runPython(`
import hashlib

try:
    hashlib.scrypt(b"auth-lab", salt=b"pyodide-fixture", n=2**10, r=8, p=1, dklen=16)
except (AttributeError, RuntimeError, ValueError):
    from authlab.passwords import Pbkdf2Params
    Pbkdf2Params(iterations=10_000, dklen=16).derive(b"auth-lab", b"pyodide-fixture")
    _authlab_password_backend = "authlab pure-Python PBKDF2-HMAC-SHA256 fallback"
else:
    _authlab_password_backend = "hashlib.scrypt"
`);
  return pyodide.runPython("_authlab_password_backend");
}

async function initialize() {
  const pyodide = await loadPyodide({ indexURL: PYODIDE_INDEX_URL });
  const response = await fetch(BUNDLE_URL, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(
      `authlab bundle is unavailable (${response.status}). `
      + "Run `python scripts/build_pyodide_bundle.py` before serving docs locally.",
    );
  }
  pyodide.unpackArchive(await response.arrayBuffer(), "zip");
  initializeExecutor(pyodide);
  pyodide.runPython("import authlab");
  const passwordBackend = detectPasswordBackend(pyodide);
  return { pyodide, passwordBackend };
}

function runtime() {
  if (!runtimePromise) {
    runtimePromise = initialize().catch((error) => {
      runtimePromise = null;
      throw error;
    });
  }
  return runtimePromise;
}

async function execute(source) {
  const incompatible = AuthLabPyodidePolicy.browserIncompatibleModule(source);
  if (incompatible) throw new Error(incompatible.message);
  const { pyodide } = await runtime();
  const callable = pyodide.globals.get("_authlab_execute");
  try {
    return String(callable(source));
  } finally {
    callable.destroy();
  }
}

self.addEventListener("message", async (event) => {
  const { id, type, source } = event.data || {};
  try {
    if (type === "initialize") {
      const { pyodide, passwordBackend } = await runtime();
      self.postMessage({
        id,
        ok: true,
        result: {
          pyodideVersion: pyodide.version,
          pythonVersion: pyodide.runPython(
            "import sys; '.'.join(map(str, sys.version_info[:3]))",
          ),
          passwordBackend,
        },
      });
      return;
    }
    if (type === "execute") {
      self.postMessage({ id, ok: true, result: await execute(source) });
      return;
    }
    throw new Error(`Unknown worker request: ${type}`);
  } catch (error) {
    self.postMessage({
      id,
      ok: false,
      error: { name: error.name || "Error", message: error.message || String(error) },
    });
  }
});
