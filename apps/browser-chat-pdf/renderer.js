(function initChatprintRenderer(root, factory) {
  const api = factory(root.ChatprintShared);
  root.ChatprintRenderer = api;
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis === "undefined" ? this : globalThis, function makeRenderer(shared) {
  "use strict";

  if (!shared) throw new Error("ChatprintShared must be loaded before the renderer.");

  const SAFE_TAGS = new Set([
    "A", "ABBR", "ARTICLE", "B", "BLOCKQUOTE", "BR", "CODE", "DD", "DEL",
    "DETAILS", "DFN", "DIV", "DL", "DT", "EM", "FIGCAPTION", "FIGURE", "H1",
    "H2", "H3", "H4", "H5", "H6", "HR", "I", "IMG", "INS", "KBD", "LI",
    "MARK", "OL", "P", "PRE", "Q", "S", "SAMP", "SECTION", "SMALL", "SPAN",
    "STRONG", "SUB", "SUMMARY", "SUP", "TABLE", "TBODY", "TD", "TFOOT", "TH",
    "THEAD", "TIME", "TR", "U", "UL", "VAR",
  ]);
  const MATH_TAGS = new Set([
    "ANNOTATION", "MATH", "MFRAC", "MI", "MN", "MO", "MOVER", "MPADDED",
    "MROOT", "MROW", "MS", "MSPACE", "MSQRT", "MSTYLE", "MSUB", "MSUBSUP",
    "MSUP", "MTABLE", "MTD", "MTEXT", "MTR", "MUNDER", "MUNDEROVER", "SEMANTICS",
  ]);
  const DROP_WITH_CONTENT = new Set([
    "BASE", "BUTTON", "DIALOG", "EMBED", "IFRAME", "INPUT", "LINK", "META",
    "NOSCRIPT", "OBJECT", "SCRIPT", "SELECT", "STYLE", "TEMPLATE", "TEXTAREA",
  ]);

  function copyAttributes(source, target, baseUrl, includeImages) {
    const tag = source.tagName.toUpperCase();
    if (tag === "A") {
      const href = shared.safeUrl(source.getAttribute("href"), baseUrl, "link");
      if (href) {
        target.setAttribute("href", href);
        target.setAttribute("rel", "noreferrer noopener");
      }
      const title = source.getAttribute("title");
      if (title) target.setAttribute("title", title.slice(0, 500));
    } else if (tag === "IMG" && includeImages) {
      const src = shared.safeUrl(source.getAttribute("src"), baseUrl, "image");
      if (src) target.setAttribute("src", src);
      const alt = source.getAttribute("alt");
      if (alt) target.setAttribute("alt", alt.slice(0, 1000));
      target.setAttribute("loading", "eager");
      target.setAttribute("decoding", "async");
    } else if (tag === "OL") {
      for (const name of ["start", "type"]) {
        if (source.hasAttribute(name)) target.setAttribute(name, source.getAttribute(name).slice(0, 20));
      }
      if (source.hasAttribute("reversed")) target.setAttribute("reversed", "");
    } else if (tag === "LI" && source.hasAttribute("value")) {
      target.setAttribute("value", source.getAttribute("value").slice(0, 20));
    } else if (["TD", "TH"].includes(tag)) {
      for (const name of ["colspan", "rowspan", "scope"]) {
        if (source.hasAttribute(name)) target.setAttribute(name, source.getAttribute(name).slice(0, 20));
      }
    } else if (tag === "TIME" && source.hasAttribute("datetime")) {
      target.setAttribute("datetime", source.getAttribute("datetime").slice(0, 100));
    } else if (tag === "DETAILS" && source.hasAttribute("open")) {
      target.setAttribute("open", "");
    } else if (tag === "MATH" && source.getAttribute("display") === "block") {
      target.setAttribute("display", "block");
    }

    if (tag === "CODE") {
      const language = Array.from(source.classList || []).find((name) => /^language-[a-z0-9_+-]+$/iu.test(name));
      if (language) target.setAttribute("class", language);
    }
  }

  function safeClone(source, targetDoc, baseUrl, includeImages) {
    if (source.nodeType === 3) return targetDoc.createTextNode(source.nodeValue || "");
    if (source.nodeType !== 1) return targetDoc.createDocumentFragment();

    const tag = source.tagName.toUpperCase();
    if (DROP_WITH_CONTENT.has(tag)) return targetDoc.createDocumentFragment();
    if (tag === "IMG" && !includeImages) {
      const alt = source.getAttribute("alt");
      return alt ? targetDoc.createTextNode(alt) : targetDoc.createDocumentFragment();
    }

    if (!SAFE_TAGS.has(tag) && !MATH_TAGS.has(tag)) {
      const fragment = targetDoc.createDocumentFragment();
      for (const child of source.childNodes) {
        fragment.appendChild(safeClone(child, targetDoc, baseUrl, includeImages));
      }
      return fragment;
    }

    const target = MATH_TAGS.has(tag)
      ? targetDoc.createElementNS("http://www.w3.org/1998/Math/MathML", tag.toLowerCase())
      : targetDoc.createElement(tag.toLowerCase());
    copyAttributes(source, target, baseUrl, includeImages);
    for (const child of source.childNodes) {
      target.appendChild(safeClone(child, targetDoc, baseUrl, includeImages));
    }
    return target;
  }

  function sanitizeInto(target, rawHtml, options = {}) {
    const targetDoc = target.ownerDocument;
    const view = targetDoc.defaultView || globalThis;
    if (typeof view.DOMParser !== "function") throw new Error("This browser cannot parse captured HTML safely.");
    const parsed = new view.DOMParser().parseFromString(String(rawHtml || ""), "text/html");
    const fragment = targetDoc.createDocumentFragment();
    for (const child of parsed.body.childNodes) {
      fragment.appendChild(safeClone(
        child,
        targetDoc,
        options.baseUrl || "https://unknown.invalid/",
        options.includeImages !== false,
      ));
    }
    target.replaceChildren(fragment);
    return target;
  }

  function waitForAssets(container, timeoutMs = 4000) {
    const images = Array.from(container.querySelectorAll("img"));
    if (!images.length) return Promise.resolve();
    const pending = images
      .filter((image) => !image.complete)
      .map((image) => new Promise((resolve) => {
        image.addEventListener("load", resolve, { once: true });
        image.addEventListener("error", resolve, { once: true });
      }));
    if (!pending.length) return Promise.resolve();
    return Promise.race([
      Promise.all(pending),
      new Promise((resolve) => setTimeout(resolve, timeoutMs)),
    ]);
  }

  return Object.freeze({ safeClone, sanitizeInto, waitForAssets });
});
