(function initChatprintShared(root, factory) {
  const api = factory();
  root.ChatprintShared = api;
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis === "undefined" ? this : globalThis, function makeShared() {
  "use strict";

  const DEFAULT_OPTIONS = Object.freeze({
    mode: "conversation",
    includeImages: true,
    includeHeader: true,
    autoPrint: false,
    paper: "a4",
    theme: "classic",
    materializeLongChats: true,
  });

  const ROLE_ALIASES = Object.freeze({
    ai: "assistant",
    answer: "assistant",
    assistant: "assistant",
    bot: "assistant",
    chatgpt: "assistant",
    claude: "assistant",
    copilot: "assistant",
    gemini: "assistant",
    human: "user",
    model: "assistant",
    page: "page",
    prompt: "user",
    query: "user",
    response: "assistant",
    system: "system",
    tool: "tool",
    user: "user",
    you: "user",
  });

  function normalizeOptions(value) {
    const input = value && typeof value === "object" ? value : {};
    return {
      mode: input.mode === "page" ? "page" : "conversation",
      includeImages: input.includeImages !== false,
      includeHeader: input.includeHeader !== false,
      autoPrint: input.autoPrint === true,
      paper: input.paper === "letter" ? "letter" : "a4",
      theme: ["classic", "clean", "compact"].includes(input.theme)
        ? input.theme
        : "classic",
      materializeLongChats: input.materializeLongChats !== false,
    };
  }

  function normalizeRole(value) {
    const normalized = String(value || "")
      .toLowerCase()
      .replace(/[\s_:./\\-]+/g, " ")
      .trim();
    if (!normalized) return "unknown";

    for (const token of normalized.split(" ")) {
      if (ROLE_ALIASES[token]) return ROLE_ALIASES[token];
    }
    return "unknown";
  }

  function roleLabel(role) {
    return {
      assistant: "Assistant",
      page: "Page",
      system: "System",
      tool: "Tool",
      unknown: "Message",
      user: "You",
    }[normalizeRole(role)];
  }

  function safeUrl(rawValue, baseUrl, kind = "link") {
    const raw = String(rawValue || "").trim();
    if (!raw) return "";
    if (kind === "image" && /^data:image\/(?:avif|gif|jpeg|png|webp);base64,/i.test(raw)) {
      return raw;
    }
    if (/^(?:#|\/[^/])/u.test(raw) && kind === "link") {
      try {
        return new URL(raw, baseUrl || "https://invalid.local/").href;
      } catch (_error) {
        return "";
      }
    }
    try {
      const parsed = new URL(raw, baseUrl || "https://invalid.local/");
      const allowed = kind === "image"
        ? new Set(["http:", "https:"])
        : new Set(["http:", "https:", "mailto:"]);
      return allowed.has(parsed.protocol) ? parsed.href : "";
    } catch (_error) {
      return "";
    }
  }

  function deriveTitle(rawTitle, hostname = "") {
    let title = String(rawTitle || "")
      .replace(/\s+[|–—-]\s+(?:ChatGPT|Claude|Gemini|Microsoft Copilot|Copilot|Perplexity)\s*$/iu, "")
      .replace(/\s+/gu, " ")
      .trim();
    if (!title || /^(?:new chat|untitled|chatgpt|claude|gemini|copilot|perplexity)$/iu.test(title)) {
      title = hostname ? `Chat from ${hostname}` : "AI conversation";
    }
    return title.slice(0, 180);
  }

  function hashText(value) {
    const text = String(value || "");
    let hash = 0x811c9dc5;
    for (let index = 0; index < text.length; index += 1) {
      hash ^= text.charCodeAt(index);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash.toString(16).padStart(8, "0");
  }

  function makeCaptureKey() {
    const random = typeof crypto !== "undefined" && crypto.getRandomValues
      ? Array.from(crypto.getRandomValues(new Uint32Array(2)), (part) => part.toString(16)).join("")
      : Math.random().toString(36).slice(2);
    return `chatprint:capture:${Date.now()}:${random}`;
  }

  function byteLength(value) {
    const serialized = typeof value === "string" ? value : JSON.stringify(value);
    return typeof TextEncoder === "function"
      ? new TextEncoder().encode(serialized).byteLength
      : serialized.length * 2;
  }

  function escapeHtml(value) {
    return String(value || "")
      .replace(/&/gu, "&amp;")
      .replace(/</gu, "&lt;")
      .replace(/>/gu, "&gt;")
      .replace(/"/gu, "&quot;")
      .replace(/'/gu, "&#39;");
  }

  function compactSource(value) {
    const source = value && typeof value === "object" ? value : {};
    let hostname = String(source.hostname || "source page").slice(0, 255);
    let url = "https://unknown.invalid/";
    try {
      const parsed = new URL(String(source.url || url));
      if (["http:", "https:"].includes(parsed.protocol)) {
        hostname = (parsed.hostname || hostname).slice(0, 255);
        url = `${parsed.origin}/`;
      } else if (parsed.protocol === "file:") {
        hostname = "local page";
        url = "file:///";
      }
    } catch (_error) {
      // The safe placeholder above keeps the emergency envelope renderable.
    }
    return { hostname: hostname || "source page", url };
  }

  function compactCapturedAt(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? new Date().toISOString() : date.toISOString();
  }

  function fitDocumentToBudget(documentValue, byteBudget = 8_000_000) {
    const source = documentValue && typeof documentValue === "object" ? documentValue : {};
    if (byteLength(source) <= byteBudget) return source;

    const result = {
      ...source,
      messages: [],
      diagnostics: {
        ...(source.diagnostics || {}),
        truncated: true,
        truncationReason: "The captured chat exceeded the browser's temporary-storage budget.",
      },
    };
    let used = byteLength({ ...result, messages: [] });
    for (const message of source.messages || []) {
      const cost = byteLength(message) + 2;
      if (used + cost > byteBudget) break;
      result.messages.push(message);
      used += cost;
    }
    if (result.messages.length === 0 && source.messages && source.messages.length > 0) {
      const first = source.messages[0];
      const availableCharacters = Math.max(256, Math.floor((byteBudget - used - 2048) / 6));
      const fallbackText = /<img\b/iu.test(String(first.html || ""))
        ? "Image"
        : (first.label || roleLabel(first.role) || "Message");
      const shortenedText = String(first.text || fallbackText).slice(0, availableCharacters);
      result.messages.push({
        id: first.id || "truncated-first-message",
        role: first.role || "unknown",
        label: first.label || roleLabel(first.role),
        text: shortenedText,
        html: `<p>${escapeHtml(shortenedText)}</p>`,
      });
    }
    result.diagnostics.originalMessageCount = (source.messages || []).length;
    result.diagnostics.messageCount = result.messages.length;
    while (result.messages.length > 0 && byteLength(result) > byteBudget) {
      const last = result.messages[result.messages.length - 1];
      if (result.messages.length > 1) {
        result.messages.pop();
      } else if ((last.text || "").length > 1) {
        const shortenedText = last.text.slice(0, Math.max(1, Math.floor(last.text.length * 0.72)));
        last.text = shortenedText;
        last.html = `<p>${escapeHtml(shortenedText)}</p>`;
      } else {
        break;
      }
      result.diagnostics.messageCount = result.messages.length;
    }
    if (byteLength(result) > byteBudget && result.messages.length > 0) {
      const first = result.messages[0];
      const oneCharacter = String(first.text || " ").slice(0, 1) || " ";
      const minimal = {
        schemaVersion: source.schemaVersion || 1,
        title: String(source.title || "Chat").slice(0, 40),
        source: compactSource(source.source),
        capturedAt: compactCapturedAt(source.capturedAt),
        mode: source.mode === "page" ? "page" : "conversation",
        adapter: String(source.adapter || "generic").slice(0, 40),
        options: normalizeOptions(source.options),
        messages: [{
          role: first.role || "unknown",
          text: oneCharacter,
          html: `<p>${escapeHtml(oneCharacter)}</p>`,
        }],
        diagnostics: {
          truncated: true,
          originalMessageCount: (source.messages || []).length,
          messageCount: 1,
        },
      };
      if (Number.isInteger(source.sourceTabId)) minimal.sourceTabId = source.sourceTabId;
      if (byteLength(minimal) <= byteBudget) return minimal;
      const empty = { messages: [], diagnostics: { truncated: true, messageCount: 0 } };
      return byteLength(empty) <= byteBudget ? empty : {};
    }
    return result;
  }

  function isSupportedPageUrl(value) {
    try {
      return ["http:", "https:", "file:"].includes(new URL(value).protocol);
    } catch (_error) {
      return false;
    }
  }

  return Object.freeze({
    DEFAULT_OPTIONS,
    byteLength,
    deriveTitle,
    escapeHtml,
    fitDocumentToBudget,
    hashText,
    isSupportedPageUrl,
    makeCaptureKey,
    normalizeOptions,
    normalizeRole,
    roleLabel,
    safeUrl,
  });
});
