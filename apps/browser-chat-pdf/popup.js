"use strict";

const api = globalThis.browser || globalThis.chrome;
const SETTINGS_KEY = "chatprint:settings";

function sendMessage(message) {
  if (globalThis.browser) return globalThis.browser.runtime.sendMessage(message);
  return new Promise((resolve, reject) => {
    api.runtime.sendMessage(message, (response) => {
      const error = api.runtime.lastError;
      if (error) reject(new Error(error.message));
      else resolve(response);
    });
  });
}

function elements() {
  return {
    autoPrint: document.querySelector("#autoPrint"),
    captureButton: document.querySelector("#captureButton"),
    captureForm: document.querySelector("#captureForm"),
    includeHeader: document.querySelector("#includeHeader"),
    includeImages: document.querySelector("#includeImages"),
    paper: document.querySelector("#paper"),
    settingsButton: document.querySelector("#settingsButton"),
    settingsPanel: document.querySelector("#advancedSettings"),
    status: document.querySelector("#status"),
    theme: document.querySelector("#theme"),
  };
}

function readForm(refs) {
  return ChatprintShared.normalizeOptions({
    mode: document.querySelector("input[name='mode']:checked").value,
    includeImages: refs.includeImages.checked,
    includeHeader: refs.includeHeader.checked,
    autoPrint: refs.autoPrint.checked,
    paper: refs.paper.value,
    theme: refs.theme.value,
  });
}

function writeForm(refs, rawOptions) {
  const options = ChatprintShared.normalizeOptions(rawOptions);
  const radio = document.querySelector(`input[name='mode'][value='${options.mode}']`);
  if (radio) radio.checked = true;
  refs.includeImages.checked = options.includeImages;
  refs.includeHeader.checked = options.includeHeader;
  refs.autoPrint.checked = options.autoPrint;
  refs.paper.value = options.paper;
  refs.theme.value = options.theme;
}

function setStatus(refs, message, state = "ready") {
  refs.status.textContent = message;
  refs.status.dataset.state = state;
}

async function init() {
  const refs = elements();
  const stored = await api.storage.local.get(SETTINGS_KEY);
  writeForm(refs, stored[SETTINGS_KEY]);

  refs.settingsButton.addEventListener("click", () => {
    const open = refs.settingsPanel.hidden;
    refs.settingsPanel.hidden = !open;
    refs.settingsButton.setAttribute("aria-expanded", String(open));
    refs.settingsButton.textContent = open ? "Done" : "Settings";
    if (open) refs.theme.focus();
  });

  refs.captureForm.addEventListener("change", () => {
    api.storage.local.set({ [SETTINGS_KEY]: readForm(refs) });
  });

  refs.captureForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const options = readForm(refs);
    refs.captureButton.disabled = true;
    setStatus(refs, options.mode === "page" ? "Reading the live page…" : "Finding every message…", "busy");
    await api.storage.local.set({ [SETTINGS_KEY]: options });
    try {
      const result = await sendMessage({ type: "chatprint:capture", options });
      if (!result || !result.ok) throw new Error(result && result.error ? result.error : "Capture failed.");
      const noun = result.messageCount === 1 ? "section" : "messages";
      const suffix = result.truncated ? " The browser storage limit shortened it." : "";
      setStatus(refs, `Preview opened with ${result.messageCount} ${noun}.${suffix}`);
    } catch (error) {
      refs.captureButton.disabled = false;
      setStatus(refs, error.message || String(error), "error");
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  init().catch((error) => {
    const status = document.querySelector("#status");
    status.textContent = error.message || String(error);
    status.dataset.state = "error";
  });
});
