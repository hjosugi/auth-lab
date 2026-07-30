"use strict";

(function publishPyodideLab(global) {
  const WORKER_URL = "assets/pyodide-worker.js";

  function createWorkerClient(worker) {
    let nextId = 1;
    const pending = new Map();
    worker.addEventListener("message", (event) => {
      const request = pending.get(event.data?.id);
      if (!request) return;
      pending.delete(event.data.id);
      if (event.data.ok) request.resolve(event.data.result);
      else {
        const error = new Error(event.data.error?.message || "Pyodide worker failed");
        error.name = event.data.error?.name || "Error";
        request.reject(error);
      }
    });
    worker.addEventListener("error", (event) => {
      for (const request of pending.values()) request.reject(event.error || new Error(event.message));
      pending.clear();
    });
    function request(type, payload = {}) {
      const id = nextId++;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        worker.postMessage({ id, type, ...payload });
      });
    }
    return {
      execute: (source) => request("execute", { source }),
      initialize: () => request("initialize"),
      terminate: () => {
        worker.terminate();
        for (const request of pending.values()) request.reject(new Error("Pyodide worker reset"));
        pending.clear();
      },
    };
  }

  function installPyodideLab(documentObject = global.document, workerFactory = null) {
    const status = documentObject?.getElementById("pyodide-status");
    if (!status) return null;
    const source = documentObject.getElementById("pyodide-source");
    const output = documentObject.getElementById("pyodide-output");
    const loadButton = documentObject.getElementById("pyodide-load");
    const runButton = documentObject.getElementById("pyodide-run");
    const resetButton = documentObject.getElementById("pyodide-reset");
    const presetButton = documentObject.getElementById("pyodide-preset");
    const makeWorker = workerFactory || (() => new Worker(WORKER_URL, { type: "module" }));
    let client = null;
    let initialized = null;

    function setBusy(busy) {
      loadButton.disabled = busy;
      runButton.disabled = busy;
      presetButton.disabled = busy;
      resetButton.disabled = !client;
      status.setAttribute("aria-busy", String(busy));
    }

    function ensureInitialized() {
      if (initialized) return initialized;
      client = createWorkerClient(makeWorker());
      setBusy(true);
      status.className = "out";
      status.textContent = "Pyodide runtime と authlab bundle を読み込み中…（初回は約10MB）";
      initialized = client.initialize()
        .then((details) => {
          status.className = "out good";
          status.textContent = `準備完了: Pyodide ${details.pyodideVersion} / Python ${details.pythonVersion} / password KDF: ${details.passwordBackend}`;
          return details;
        })
        .catch((error) => {
          client?.terminate();
          client = null;
          initialized = null;
          status.className = "out bad";
          status.textContent = `読み込み失敗: ${error.name}: ${error.message}`;
          throw error;
        })
        .finally(() => setBusy(false));
      return initialized;
    }

    async function run() {
      const incompatible = global.AuthLabPyodidePolicy.browserIncompatibleModule(source.value);
      if (incompatible) {
        output.className = "out bad";
        output.textContent = incompatible.message;
        return;
      }
      setBusy(true);
      output.className = "out";
      output.textContent = "実行中…";
      try {
        await ensureInitialized();
        setBusy(true);
        output.textContent = await client.execute(source.value) || "(出力なし)";
        output.className = "out good";
      } catch (error) {
        output.textContent = `${error.name}: ${error.message}`;
        output.className = "out bad";
      } finally {
        setBusy(false);
      }
    }

    function resetWorker() {
      client?.terminate();
      client = null;
      initialized = null;
      status.className = "out";
      status.textContent = "未読み込み。タブを開くか「runtime を読み込む」を押してください。";
      output.className = "out";
      output.textContent = "まだ実行していません。";
      setBusy(false);
    }

    source.value = global.AuthLabPyodidePolicy.DEFAULT_SOURCE;
    loadButton.addEventListener("click", () => ensureInitialized().catch(() => {}));
    runButton.addEventListener("click", run);
    resetButton.addEventListener("click", resetWorker);
    presetButton.addEventListener("click", () => {
      source.value = global.AuthLabPyodidePolicy.DEFAULT_SOURCE;
      source.focus();
    });
    source.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
        event.preventDefault();
        run();
      }
    });
    documentObject.addEventListener("authlab:tabshown", (event) => {
      if (event.detail?.id === "t-pyodide") ensureInitialized().catch(() => {});
    });
    setBusy(false);

    return { ensureInitialized, resetWorker, run };
  }

  const api = { WORKER_URL, createWorkerClient, installPyodideLab };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.AuthLabPyodide = api;
  if (global.document) {
    global.document.addEventListener("DOMContentLoaded", () => {
      api.lab = installPyodideLab(global.document);
    });
  }
}(typeof globalThis === "undefined" ? window : globalThis));
