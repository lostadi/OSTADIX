"use strict";

importScripts("shared.js");

const api = globalThis.browser || globalThis.chrome;
const shared = globalThis.ChatprintShared;
const CAPTURE_PREFIX = "chatprint:capture:";
const STALE_CAPTURE_AGE_MS = 10 * 60 * 1000;

function storageArea() {
  return api.storage.session || api.storage.local;
}

async function captureBudget() {
  const area = storageArea();
  const stored = await area.get(null);
  const now = Date.now();
  const staleKeys = Object.keys(stored).filter((key) => {
    if (!key.startsWith(CAPTURE_PREFIX)) return false;
    const timestamp = Number(key.split(":")[2]);
    return !Number.isFinite(timestamp) || now - timestamp > STALE_CAPTURE_AGE_MS;
  });
  if (staleKeys.length) await area.remove(staleKeys);

  const quota = Number(area.QUOTA_BYTES) || 1_000_000;
  const used = typeof area.getBytesInUse === "function"
    ? Number(await area.getBytesInUse(null)) || 0
    : 0;
  const available = quota - used - 64_000;
  if (available < 128_000) {
    throw new Error("Not enough temporary browser storage is available. Let an older Chatprint preview finish opening, then try again.");
  }
  // Session quota is an in-memory estimate rather than exact JSON bytes, so
  // retain headroom for object/string allocation as well as the storage key.
  return Math.min(8_000_000, Math.floor(available * 0.8));
}

function activeTab() {
  return api.tabs.query({ active: true, currentWindow: true }).then((tabs) => tabs[0]);
}

async function captureTab(requestedTabId, rawOptions) {
  const tab = requestedTabId
    ? await api.tabs.get(requestedTabId)
    : await activeTab();
  if (!tab || !Number.isInteger(tab.id)) {
    throw new Error("No active browser tab is available.");
  }
  if (!shared.isSupportedPageUrl(tab.url || "")) {
    throw new Error("Chatprint works on normal web pages. Browser settings and extension pages cannot be captured.");
  }

  const options = shared.normalizeOptions(rawOptions);
  const byteBudget = await captureBudget();
  await api.scripting.executeScript({
    target: { tabId: tab.id },
    files: ["shared.js", "extractor.js"],
  });
  const injection = await api.scripting.executeScript({
    target: { tabId: tab.id },
    func: async (captureOptions, maximumBytes) => {
      const documentValue = await globalThis.ChatprintExtractor.capture(captureOptions);
      return globalThis.ChatprintShared.fitDocumentToBudget(documentValue, maximumBytes);
    },
    args: [options, byteBudget],
  });
  const captured = injection && injection[0] && injection[0].result;
  if (!captured || !Array.isArray(captured.messages) || captured.messages.length === 0) {
    throw new Error("No readable page text was found. Try Whole page mode after the chat has finished loading.");
  }

  captured.sourceTabId = tab.id;
  const bounded = shared.fitDocumentToBudget(captured, byteBudget);
  if (!bounded.messages.length) {
    throw new Error("The captured page was too large to transfer safely. Try text-only Conversation mode.");
  }
  const key = shared.makeCaptureKey();
  await storageArea().set({ [key]: bounded });
  let preview;
  try {
    preview = await api.tabs.create({
      url: api.runtime.getURL(`preview.html?capture=${encodeURIComponent(key)}`),
    });
  } catch (error) {
    await storageArea().remove(key);
    throw error;
  }

  return {
    ok: true,
    title: bounded.title,
    messageCount: bounded.messages.length,
    previewTabId: preview.id,
    truncated: bounded.diagnostics && bounded.diagnostics.truncated === true,
  };
}

function reportActionError(error) {
  console.error("Chatprint capture failed", error);
  api.action.setBadgeBackgroundColor({ color: "#b42318" });
  api.action.setBadgeText({ text: "!" });
  setTimeout(() => api.action.setBadgeText({ text: "" }), 4000);
}

api.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.type !== "chatprint:capture") return false;
  captureTab(message.tabId, message.options)
    .then((result) => sendResponse(result))
    .catch((error) => sendResponse({ ok: false, error: error.message || String(error) }));
  return true;
});

api.commands.onCommand.addListener((command) => {
  if (command !== "capture-chat") return;
  api.storage.local.get("chatprint:settings")
    .then((stored) => captureTab(undefined, stored["chatprint:settings"]))
    .catch(reportActionError);
});
