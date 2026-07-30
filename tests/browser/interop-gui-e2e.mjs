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

async function screenshot(session, name) {
  const evidenceDirectory = path.join(process.cwd(), ".tmp", "browser-evidence");
  await mkdir(evidenceDirectory, { recursive: true });
  const image = await session.devtools.command(
    "Page.captureScreenshot",
    { format: "png", fromSurface: true, captureBeyondViewport: false },
    session.sessionId,
  );
  await writeFile(path.join(evidenceDirectory, name), Buffer.from(image.data, "base64"));
}

async function main() {
  const session = await createBrowserSession("auth-lab-interop-gui-");
  try {
    await navigate(session);
    await waitForExpression(session, "window.AuthLabInterop", {
      message: "interoperability explorer did not install",
    });
    const desktop = await evaluate(session, `(async () => {
      showTab("t-interop", null);
      await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      const select = document.getElementById("interop-protocol");
      select.value = "saml";
      select.dispatchEvent(new Event("change", {bubbles: true}));
      const panel = document.getElementById("t-interop");
      const tabs = document.querySelector(".tabs");
      const explorer = document.querySelector(".interop-explorer");
      explorer.scrollIntoView({block: "start"});
      window.scrollBy(0, -tabs.offsetHeight - 8);
      return {
        hash: location.hash,
        active: document.querySelector(".tab-btn.active").dataset.tabTarget,
        product: document.getElementById("interop-product").textContent,
        steps: document.querySelectorAll("#interop-wire li").length,
        negative: document.getElementById("interop-negative").textContent,
        externalDockerClaim: panel.textContent.includes("Pages上ではDockerを起動しません"),
        horizontalOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      };
    })()`);
    assert.deepEqual(
      {
        hash: desktop.hash,
        active: desktop.active,
        product: desktop.product,
        steps: desktop.steps,
        externalDockerClaim: desktop.externalDockerClaim,
      },
      {
        hash: "#t-interop",
        active: "t-interop",
        product: "Keycloak 26.7.0",
        steps: 4,
        externalDockerClaim: true,
      },
    );
    assert.match(desktop.negative, /拒否/u);
    assert.ok(desktop.horizontalOverflow <= 0);
    await screenshot(session, "interop-desktop.png");

    await session.devtools.command("Emulation.setDeviceMetricsOverride", {
      width: 390,
      height: 844,
      deviceScaleFactor: 1,
      mobile: true,
    }, session.sessionId);
    await evaluate(session, `(async () => {
      window.dispatchEvent(new Event("resize"));
      await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      const panel = document.getElementById("t-interop");
      const tabs = document.querySelector(".tabs");
      const explorer = document.querySelector(".interop-explorer");
      explorer.scrollIntoView({block: "start"});
      window.scrollBy(0, -tabs.offsetHeight - 8);
    })()`);
    const mobile = await evaluate(session, `(() => {
      const tabs = document.querySelector(".tabs").getBoundingClientRect();
      const active = document.querySelector(".tab-btn.active").getBoundingClientRect();
      const links = [...document.querySelectorAll(".interop-links .act")]
        .map((link) => link.getBoundingClientRect());
      return {
        viewport: document.documentElement.clientWidth,
        content: document.documentElement.scrollWidth,
        activeTabVisible: active.left >= tabs.left && active.right <= tabs.right,
        linkWidths: links.map(({width}) => width),
        linkHeights: links.map(({height}) => height),
        topologyColumns: getComputedStyle(document.querySelector(".interop-topology"))
          .gridTemplateColumns.split(" ").length,
      };
    })()`);
    assert.ok(mobile.content <= mobile.viewport);
    assert.equal(mobile.activeTabVisible, true);
    assert.ok(
      mobile.linkWidths.every((width) => width >= 280),
      `mobile links are too narrow: ${JSON.stringify(mobile)}`,
    );
    assert.ok(
      mobile.linkHeights.every((height) => height >= 44),
      `mobile links are too short: ${JSON.stringify(mobile)}`,
    );
    assert.equal(mobile.topologyColumns, 1);
    await screenshot(session, "interop-mobile.png");

    console.log(JSON.stringify({
      browser: session.executable,
      origin: session.origin,
      protocol: "SAML",
      desktop: "no overflow and live explorer",
      mobile: "single-column topology, touch targets, active tab visible",
    }));
  } finally {
    await session.close();
  }
}

await main();
