#!/usr/bin/env node

import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import {
  createBrowserSession,
  evaluate,
  navigate,
  waitForExpression,
} from "./support/browser-harness.mjs";

async function main() {
  const session = await createBrowserSession("auth-lab-pyodide-");
  try {
    await navigate(session);
    await waitForExpression(session, "window.AuthLabPyodide?.lab", {
      message: "Pyodide lab did not install",
    });
    const loadedBeforeTab = await evaluate(
      session,
      "performance.getEntriesByType('resource').some((entry) => entry.name.includes('/pyodide/'))",
    );
    assert.equal(loadedBeforeTab, false, "initial page must not load the Pyodide runtime");

    const keyboardNavigation = await evaluate(session, `(() => {
      const current = document.querySelector('[data-tab-target="t-webauthn-native"]');
      current.focus();
      current.dispatchEvent(new KeyboardEvent("keydown", {key:"ArrowRight",bubbles:true}));
      return {
        active: document.querySelector(".tab-btn.active").dataset.tabTarget,
        hash: location.hash,
      };
    })()`);
    assert.deepEqual(keyboardNavigation, { active: "t-pyodide", hash: "#t-pyodide" });

    const details = await evaluate(session, "AuthLabPyodide.lab.ensureInitialized()", 120_000);
    assert.equal(details.pyodideVersion, "314.0.2");
    assert.match(details.pythonVersion, /^3\.14\./u);
    assert.match(details.passwordBackend, /hashlib\.scrypt|PBKDF2-HMAC-SHA256 fallback/u);

    const execution = await evaluate(session, `(async () => {
      await AuthLabPyodide.lab.run();
      return {
        output: document.getElementById("pyodide-output").textContent,
        status: document.getElementById("pyodide-status").textContent,
      };
    })()`, 120_000);
    assert.match(execution.output, /VALID: learner/u);
    assert.match(execution.output, /TAMPERED: REFUSED/u);
    assert.match(execution.output, /InvalidSignature/u);

    const evidenceDirectory = path.join(process.cwd(), ".tmp", "browser-evidence");
    await mkdir(evidenceDirectory, { recursive: true });
    await evaluate(session, `(() => {
      const card = document.querySelector("#t-pyodide .card.demo");
      const tabs = document.querySelector(".tabs");
      window.scrollTo({top: card.offsetTop - tabs.offsetHeight - 8});
    })()`);
    const desktop = await session.devtools.command(
      "Page.captureScreenshot",
      { format: "png", fromSurface: true, captureBeyondViewport: false },
      session.sessionId,
    );
    await writeFile(
      path.join(evidenceDirectory, "pyodide-desktop.png"),
      Buffer.from(desktop.data, "base64"),
    );

    const guard = await evaluate(session, `(async () => {
      document.getElementById("pyodide-source").value = "import socket";
      await AuthLabPyodide.lab.run();
      return document.getElementById("pyodide-output").textContent;
    })()`);
    assert.match(guard, /drills\/12_mtls\.py/u);

    await session.devtools.command("Emulation.setDeviceMetricsOverride", {
      width: 390,
      height: 844,
      deviceScaleFactor: 1,
      mobile: true,
    }, session.sessionId);
    await evaluate(session, "window.dispatchEvent(new Event('resize'))");
    const mobileLayout = await evaluate(session, `(() => {
      const editor = document.getElementById("pyodide-source").getBoundingClientRect();
      const tabs = document.querySelector(".tabs").getBoundingClientRect();
      const active = document.querySelector(".tab-btn.active").getBoundingClientRect();
      const buttons = [...document.querySelectorAll(".pyodide-actions .act")]
        .map((button) => button.getBoundingClientRect().width);
      return {
        viewport: document.documentElement.clientWidth,
        content: document.documentElement.scrollWidth,
        editorWidth: editor.width,
        buttons,
        activeTabVisible: active.left >= tabs.left && active.right <= tabs.right,
      };
    })()`);
    assert.ok(mobileLayout.content <= mobileLayout.viewport);
    assert.ok(mobileLayout.editorWidth <= mobileLayout.viewport);
    assert.ok(mobileLayout.buttons.every((width) => width >= 300));
    assert.equal(mobileLayout.activeTabVisible, true);
    await evaluate(session, `(() => {
      const card = document.querySelector("#t-pyodide .card.demo");
      const tabs = document.querySelector(".tabs");
      window.scrollTo({top: card.offsetTop - tabs.offsetHeight - 8});
    })()`);
    const mobile = await session.devtools.command(
      "Page.captureScreenshot",
      { format: "png", fromSurface: true, captureBeyondViewport: false },
      session.sessionId,
    );
    await writeFile(
      path.join(evidenceDirectory, "pyodide-mobile.png"),
      Buffer.from(mobile.data, "base64"),
    );

    const reset = await evaluate(session, `(async () => {
      document.getElementById("pyodide-source").value = "while True:\\n    pass";
      const execution = AuthLabPyodide.lab.run();
      await new Promise((resolve) => setTimeout(resolve, 100));
      AuthLabPyodide.lab.resetWorker();
      await execution;
      return {
        resetDisabled: document.getElementById("pyodide-reset").disabled,
        status: document.getElementById("pyodide-status").textContent,
      };
    })()`);
    assert.equal(reset.resetDisabled, true);
    assert.match(reset.status, /未読み込み/u);

    console.log(JSON.stringify({
      browser: session.executable,
      origin: session.origin,
      pyodide: details.pyodideVersion,
      python: details.pythonVersion,
      passwordBackend: details.passwordBackend,
      scenarios: ["JWT valid", "JWT tampered", "socket guard", "infinite-loop reset"],
      gui: ["keyboard tabs", "desktop screenshot", "mobile overflow and touch controls"],
    }));
  } finally {
    await session.close();
  }
}

await main();
