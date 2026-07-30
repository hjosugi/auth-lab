"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  CONTRAST_PALETTES,
  SEQUENCES,
  createSequenceState,
  currentView,
  installSequencePlayer,
} = require("../../docs/assets/sequences.js");

const root = path.resolve(__dirname, "../..");

class FakeElement {
  constructor(value = "") {
    this.value = value;
    this.textContent = "";
    this.disabled = false;
    this.lang = "";
    this.listeners = new Map();
  }

  addEventListener(type, listener) {
    this.listeners.set(type, listener);
  }

  dispatch(type, values = {}) {
    const event = {
      key: "",
      altKey: false,
      ctrlKey: false,
      metaKey: false,
      defaultPrevented: false,
      preventDefault() {
        this.defaultPrevented = true;
      },
      ...values,
    };
    this.listeners.get(type)?.(event);
    return event;
  }
}

function fakeDocument() {
  const ids = [
    "sequence-shell",
    "sequence-card",
    "sequence-from",
    "sequence-to",
    "sequence-message",
    "sequence-narration",
    "sequence-asset",
    "sequence-boundary",
    "sequence-binding",
    "sequence-asset-label",
    "sequence-boundary-label",
    "sequence-binding-label",
    "sequence-progress",
    "sequence-previous",
    "sequence-next",
    "sequence-reset",
  ];
  const elements = Object.fromEntries(ids.map((id) => [id, new FakeElement()]));
  elements["sequence-flow"] = new FakeElement("oauth");
  elements["sequence-language"] = new FakeElement("ja");
  return {
    elements,
    getElementById(id) {
      return elements[id] || null;
    },
  };
}

function luminance(hex) {
  const channels = hex.match(/[a-f0-9]{2}/giu).map((value) => {
    const normalized = Number.parseInt(value, 16) / 255;
    return normalized <= 0.04045
      ? normalized / 12.92
      : ((normalized + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrastRatio(first, second) {
  const high = Math.max(luminance(first), luminance(second));
  const low = Math.min(luminance(first), luminance(second));
  return (high + 0.05) / (low + 0.05);
}

test("all four protocols carry equivalent localized concepts on every step", () => {
  assert.deepEqual(Object.keys(SEQUENCES), ["oauth", "saml", "kerberos", "webauthn"]);
  for (const [flowName, flow] of Object.entries(SEQUENCES)) {
    assert.ok(flow.steps.length >= 5, `${flowName} must have at least five steps`);
    for (const [index, sequenceStep] of flow.steps.entries()) {
      assert.ok(sequenceStep.from && sequenceStep.to);
      for (const field of ["message", "narration", "asset", "boundary", "binding"]) {
        assert.ok(sequenceStep[field].ja, `${flowName}[${index}].${field}.ja`);
        assert.ok(sequenceStep[field].en, `${flowName}[${index}].${field}.en`);
      }
      for (const field of ["asset", "boundary", "binding"]) {
        assert.ok(sequenceStep[field].id, `${flowName}[${index}].${field}.id`);
      }
    }
  }
});

test("localized view keeps the protocol facts while changing narration", () => {
  const state = createSequenceState("saml", "ja");
  const japanese = currentView(state);
  state.locale = "en";
  const english = currentView(state);
  assert.equal(japanese.step.asset.id, english.step.asset.id);
  assert.equal(japanese.step.boundary.id, english.step.boundary.id);
  assert.equal(japanese.step.binding.id, english.step.binding.id);
  assert.notEqual(japanese.narration, english.narration);
});

test("buttons move one message at a time and stay within bounds", () => {
  const document = fakeDocument();
  const controller = installSequencePlayer(document);
  const { elements } = document;
  assert.equal(controller.getState().index, 0);
  assert.equal(elements["sequence-previous"].disabled, true);

  elements["sequence-next"].dispatch("click");
  assert.equal(controller.getState().index, 1);
  elements["sequence-previous"].dispatch("click");
  elements["sequence-previous"].dispatch("click");
  assert.equal(controller.getState().index, 0);

  for (let index = 0; index < 20; index += 1) {
    elements["sequence-next"].dispatch("click");
  }
  assert.equal(controller.getState().index, SEQUENCES.oauth.steps.length - 1);
  assert.equal(elements["sequence-next"].disabled, true);
});

test("flow and language controls reset and rerender the player", () => {
  const document = fakeDocument();
  const controller = installSequencePlayer(document);
  const { elements } = document;
  elements["sequence-next"].dispatch("click");
  elements["sequence-flow"].value = "kerberos";
  elements["sequence-flow"].dispatch("change");
  assert.deepEqual(controller.getState(), { flow: "kerberos", locale: "ja", index: 0 });

  const japanese = elements["sequence-narration"].textContent;
  elements["sequence-language"].value = "en";
  elements["sequence-language"].dispatch("change");
  assert.equal(controller.getState().locale, "en");
  assert.notEqual(elements["sequence-narration"].textContent, japanese);
  assert.equal(elements["sequence-shell"].lang, "en");
});

test("Arrow, Home, and End keys operate the focused player", () => {
  const document = fakeDocument();
  const controller = installSequencePlayer(document);
  const shell = document.elements["sequence-shell"];
  const right = shell.dispatch("keydown", { key: "ArrowRight" });
  assert.equal(right.defaultPrevented, true);
  assert.equal(controller.getState().index, 1);

  shell.dispatch("keydown", { key: "End" });
  assert.equal(controller.getState().index, SEQUENCES.oauth.steps.length - 1);
  shell.dispatch("keydown", { key: "Home" });
  assert.equal(controller.getState().index, 0);

  const modified = shell.dispatch("keydown", { key: "ArrowRight", ctrlKey: true });
  assert.equal(modified.defaultPrevented, false);
  assert.equal(controller.getState().index, 0);
});

test("markup and CSS expose focus, live updates, and reduced-motion handling", () => {
  const html = fs.readFileSync(path.join(root, "docs/index.html"), "utf8");
  const css = fs.readFileSync(path.join(root, "docs/assets/lab.css"), "utf8");
  assert.match(html, /id="sequence-shell"[^>]*tabindex="0"/u);
  assert.match(html, /id="sequence-narration"[^>]*aria-live="polite"/u);
  assert.match(html, /aria-keyshortcuts="ArrowLeft"/u);
  assert.match(html, /aria-keyshortcuts="ArrowRight"/u);
  assert.match(css, /:focus-visible/u);
  assert.match(css, /prefers-reduced-motion:\s*reduce/u);
});

test("semantic colors meet WCAG AA normal-text contrast in both themes", () => {
  const css = fs.readFileSync(path.join(root, "docs/assets/lab.css"), "utf8");
  for (const palette of Object.values(CONTRAST_PALETTES)) {
    for (const role of ["asset", "boundary", "binding"]) {
      assert.ok(
        contrastRatio(palette[role], palette.background) >= 4.5,
        `${role} must reach 4.5:1 on ${palette.background}`,
      );
      assert.ok(css.includes(palette[role]), `${palette[role]} must be wired into CSS`);
    }
  }
});
