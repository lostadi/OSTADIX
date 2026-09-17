"use strict";

const api = globalThis.browser || globalThis.chrome;
let capture = null;

function storageArea() {
  return api.storage.session || api.storage.local;
}

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

function refs() {
  return {
    captureAgainButton: document.querySelector("#captureAgainButton"),
    capturedDate: document.querySelector("#capturedDate"),
    documentHeader: document.querySelector("#documentHeader"),
    documentTitle: document.querySelector("#documentTitle"),
    imagesSelect: document.querySelector("#imagesSelect"),
    messageTemplate: document.querySelector("#messageTemplate"),
    messages: document.querySelector("#messages"),
    notice: document.querySelector("#notice"),
    pageRule: document.querySelector("#pageRule"),
    paper: document.querySelector("#paper"),
    paperSelect: document.querySelector("#paperSelect"),
    printButton: document.querySelector("#printButton"),
    sourceLink: document.querySelector("#sourceLink"),
    themeSelect: document.querySelector("#themeSelect"),
    titleInput: document.querySelector("#titleInput"),
  };
}

function showNotice(elements, text, kind = "warning") {
  elements.notice.textContent = text;
  elements.notice.dataset.kind = kind;
  elements.notice.hidden = false;
}

function diagnosticNotice(value) {
  const diagnostics = value.diagnostics || {};
  const notes = [];
  if (diagnostics.streaming) notes.push("The response was still being generated, so the final words may be missing.");
  if (diagnostics.hitScrollLimit) notes.push("This unusually long virtualized chat reached the capture scan limit.");
  if (diagnostics.truncated) notes.push(diagnostics.truncationReason || "The capture was shortened to fit browser storage.");
  if (diagnostics.fellBackToPage) notes.push("No supported message structure was found, so Chatprint captured the main page content instead.");
  return notes.join(" ");
}

function setPaper(elements, value) {
  const paper = value === "letter" ? "letter" : "a4";
  elements.paper.dataset.paper = paper;
  elements.paperSelect.value = paper;
  elements.pageRule.textContent = paper === "letter"
    ? "@page { size: Letter; margin: 0.62in 0.66in 0.66in; }"
    : "@page { size: A4; margin: 15mm 16mm 16mm; }";
}

function setTheme(elements, value) {
  const theme = ["classic", "clean", "compact"].includes(value) ? value : "classic";
  document.body.dataset.theme = theme;
  elements.themeSelect.value = theme;
}

function setImages(elements, value) {
  const imageMode = value === "hide" ? "hide" : "show";
  document.body.dataset.images = imageMode;
  elements.imagesSelect.value = imageMode;
}

function updateTitle(elements) {
  const title = elements.titleInput.value.trim() || "AI conversation";
  elements.documentTitle.textContent = title;
  document.title = `${title} — Chatprint`;
}

function renderMessages(elements, value) {
  const fragment = document.createDocumentFragment();
  for (const message of value.messages) {
    const instance = elements.messageTemplate.content.cloneNode(true);
    const section = instance.querySelector(".message");
    const role = ChatprintShared.normalizeRole(message.role);
    section.dataset.role = role;
    instance.querySelector(".message__role").textContent = message.label || ChatprintShared.roleLabel(role);
    const body = instance.querySelector(".message__body");
    ChatprintRenderer.sanitizeInto(body, message.html, {
      baseUrl: value.source.url,
      includeImages: value.options.includeImages,
    });
    if (!body.textContent.trim() && message.text) body.textContent = message.text;
    fragment.appendChild(instance);
  }
  elements.messages.replaceChildren(fragment);
}

async function printDocument(elements) {
  elements.printButton.disabled = true;
  try {
    if (document.fonts && document.fonts.ready) await document.fonts.ready;
    await ChatprintRenderer.waitForAssets(elements.messages);
    window.print();
  } finally {
    elements.printButton.disabled = false;
  }
}

function currentOptions(elements) {
  return ChatprintShared.normalizeOptions({
    ...capture.options,
    paper: elements.paperSelect.value,
    theme: elements.themeSelect.value,
    includeImages: elements.imagesSelect.value === "show",
    autoPrint: false,
  });
}

async function init() {
  const elements = refs();
  const params = new URLSearchParams(location.search);
  const key = params.get("capture");
  if (!key || !key.startsWith("chatprint:capture:")) {
    throw new Error("This preview link does not contain a valid capture key.");
  }

  const area = storageArea();
  const stored = await area.get(key);
  capture = stored[key];
  await area.remove(key);
  history.replaceState(null, "", location.pathname);
  if (!capture || capture.schemaVersion !== 1 || !Array.isArray(capture.messages)) {
    throw new Error("The temporary capture expired. Return to the chat and create a new preview.");
  }

  capture.options = ChatprintShared.normalizeOptions(capture.options);
  if (!capture.options.includeImages) {
    elements.imagesSelect.querySelector("option[value='show']").disabled = true;
    elements.imagesSelect.disabled = true;
    elements.imagesSelect.title = "Images were excluded during capture. Capture again to include them.";
  }
  elements.titleInput.value = capture.title;
  updateTitle(elements);
  elements.documentHeader.hidden = !capture.options.includeHeader;
  elements.sourceLink.textContent = capture.source.hostname;
  elements.sourceLink.href = ChatprintShared.safeUrl(capture.source.url, capture.source.url, "link") || "#";
  elements.capturedDate.dateTime = capture.capturedAt;
  elements.capturedDate.textContent = new Intl.DateTimeFormat(undefined, {
    dateStyle: "long",
    timeStyle: "short",
  }).format(new Date(capture.capturedAt));
  setTheme(elements, capture.options.theme);
  setPaper(elements, capture.options.paper);
  setImages(elements, capture.options.includeImages ? "show" : "hide");
  renderMessages(elements, capture);

  const warning = diagnosticNotice(capture);
  if (warning) showNotice(elements, warning);

  elements.titleInput.addEventListener("input", () => updateTitle(elements));
  elements.themeSelect.addEventListener("change", () => setTheme(elements, elements.themeSelect.value));
  elements.paperSelect.addEventListener("change", () => setPaper(elements, elements.paperSelect.value));
  elements.imagesSelect.addEventListener("change", () => setImages(elements, elements.imagesSelect.value));
  elements.printButton.addEventListener("click", () => {
    printDocument(elements).catch((error) => showNotice(elements, error.message || String(error), "error"));
  });
  elements.captureAgainButton.addEventListener("click", async () => {
    elements.captureAgainButton.disabled = true;
    try {
      const result = await sendMessage({
        type: "chatprint:capture",
        tabId: capture.sourceTabId,
        options: currentOptions(elements),
      });
      if (!result || !result.ok) throw new Error(result && result.error ? result.error : "Capture failed.");
      window.close();
    } catch (error) {
      elements.captureAgainButton.disabled = false;
      showNotice(elements, error.message || String(error), "error");
    }
  });

  if (capture.options.autoPrint) {
    setTimeout(() => {
      printDocument(elements).catch((error) => showNotice(elements, error.message || String(error), "error"));
    }, 300);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  init().catch((error) => {
    const elements = refs();
    elements.paper.hidden = true;
    showNotice(elements, error.message || String(error), "error");
  });
});
