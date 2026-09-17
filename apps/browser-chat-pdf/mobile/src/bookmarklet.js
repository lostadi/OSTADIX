(function initChatprintMobile(root, factory) {
  const api = factory(root, root.ChatprintShared);
  root.ChatprintMobile = api;
  if (typeof module === "object" && module.exports) module.exports = api;
})(typeof globalThis === "undefined" ? this : globalThis, function makeChatprintMobile(root, shared) {
  "use strict";

  if (!shared) throw new Error("Chatprint mobile requires ChatprintShared.");

  // Compact structured-tree capture adapted from extractor.js and renderer.js.
  // It avoids HTML-string sinks so strict Trusted Types pages still work.
  const SKIP = new Set([
    "BUTTON", "DIALOG", "EMBED", "IFRAME", "INPUT", "LINK", "META", "NOSCRIPT",
    "OBJECT", "OPTION", "SCRIPT", "SELECT", "STYLE", "TEMPLATE", "TEXTAREA",
  ]);
  const SAFE = new Set([
    "A", "ABBR", "ARTICLE", "B", "BLOCKQUOTE", "BR", "CODE", "DD", "DEL",
    "DETAILS", "DFN", "DIV", "DL", "DT", "EM", "FIGCAPTION", "FIGURE", "H1",
    "H2", "H3", "H4", "H5", "H6", "HR", "I", "IMG", "INS", "KBD", "LI",
    "MARK", "OL", "P", "PRE", "Q", "S", "SAMP", "SECTION", "SMALL", "SPAN",
    "STRONG", "SUB", "SUMMARY", "SUP", "TABLE", "TBODY", "TD", "TFOOT", "TH",
    "THEAD", "TIME", "TR", "U", "UL", "VAR",
  ]);
  const MATH = new Set([
    "ANNOTATION", "MATH", "MFRAC", "MI", "MN", "MO", "MOVER", "MPADDED",
    "MROOT", "MROW", "MS", "MSPACE", "MSQRT", "MSTYLE", "MSUB", "MSUBSUP",
    "MSUP", "MTABLE", "MTD", "MTEXT", "MTR", "MUNDER", "MUNDEROVER", "SEMANTICS",
  ]);
  const GROUPS = [
    { h: ["chatgpt.com", "chat.openai.com"], q: [["[data-message-author-role]"], ["article[data-testid^='conversation-turn-']"]] },
    { h: ["claude.ai"], q: [["[data-testid='user-message']", "user"], ["[data-testid='assistant-message'],[data-testid='model-message']", "assistant"]] },
    { h: ["gemini.google.com", "bard.google.com"], q: [["user-query", "user"], ["model-response", "assistant"]] },
    { h: ["copilot.microsoft.com", "bing.com"], q: [["[data-content='user-message'],[data-testid='user-message']", "user"], ["[data-content='ai-message'],[data-testid='assistant-message']", "assistant"]] },
    { h: ["perplexity.ai"], q: [["[data-testid='user-message']", "user"], ["[data-testid='answer'],[data-testid='assistant-message']", "assistant"]] },
  ];
  const GENERIC = [
    { q: [["[data-message-author-role],[data-author-role]"]] },
    { q: [["[data-role='user'],[data-role='human']", "user"], ["[data-role='assistant'],[data-role='model'],[data-role='ai']", "assistant"]] },
    { q: [["user-query,user-message", "user"], ["model-response,assistant-message,ai-message", "assistant"]] },
    { q: [["[role='article'][aria-label*='user' i],article[aria-label*='you' i]", "user"], ["[role='article'][aria-label*='assistant' i],article[aria-label*='response' i]", "assistant"]] },
    { q: [["main article,[role='main'] article"]], low: true },
  ];
  const CSS = `
:root{color-scheme:light;--blue:#155eef;--ink:#111827;--muted:#667085;--line:#d0d5dd;--paper:#fff;--work:#f3f4f6;--ui:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--doc:Charter,"Iowan Old Style","Palatino Linotype",Georgia,serif}*{box-sizing:border-box}html{background:var(--work)}body{min-width:300px;min-height:100vh;margin:0;background:var(--work);color:var(--ink);font-family:var(--ui)}button,input,select{font:inherit}.screen-header{display:flex;align-items:center;justify-content:space-between;min-height:74px;padding:14px 22px;border-bottom:1px solid var(--line);background:#fff}.brand{display:flex;align-items:center;gap:12px;font-size:25px;font-weight:750;letter-spacing:-.04em}.icon{width:31px;height:31px;fill:none;stroke:currentColor;stroke-linecap:round;stroke-linejoin:round;stroke-width:1.8}.back{min-height:44px;padding:0;border:0;background:transparent;color:var(--blue);font-size:15px}.main{width:min(100% - 32px,770px);margin:auto;padding:30px 0 145px}.title-wrap{position:relative}.title{width:100%;min-height:56px;padding:0 50px 0 15px;border:2px solid var(--blue);border-radius:7px;background:#fff;color:#171717;font:20px/1 var(--doc);box-shadow:0 0 0 3px rgba(21,94,239,.08)}.edit{position:absolute;right:15px;top:16px;width:23px;height:23px;color:#475467}.options{margin:8px 2px 0;color:var(--blue);font-size:12px}.options summary{cursor:pointer}.options-panel{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-top:7px}.options select{min-width:0;min-height:36px;border:1px solid var(--line);border-radius:5px;background:#fff;color:var(--ink);font-size:11px}.status{min-height:27px;padding:9px 3px 0;color:var(--muted);font-size:12px}.status[data-kind=error]{color:#b42318}.paper{min-height:900px;margin-top:9px;padding:39px 30px 48px;background:var(--paper);box-shadow:0 2px 12px rgba(16,24,40,.18);color:#171717;font:15.5px/1.5 var(--doc)}.document-header{margin-bottom:23px}.document-header h1{margin:0;padding-bottom:7px;border-bottom:1px solid #667085;font-size:24px;line-height:1.18;letter-spacing:-.02em}.meta{display:flex;justify-content:space-between;gap:15px;margin-top:7px;color:#344054;font-size:11px}.meta a{color:inherit;text-decoration:none;overflow-wrap:anywhere}.message{margin:0 0 18px;padding:0 0 18px;border-bottom:1px solid var(--line)}.message:last-child{margin:0;padding:0;border:0}.role{margin:0 0 4px;font-size:14px;line-height:1.35}.body>:first-child{margin-top:0}.body>:last-child{margin-bottom:0}.body p,.body div{margin:0 0 .72em}.body h1,.body h2,.body h3,.body h4,.body h5,.body h6{margin:1.05em 0 .38em;break-after:avoid-page;line-height:1.25}.body h1,.body h2{font-size:1.18em}.body h3{font-size:1.07em}.body ul,.body ol{margin:.5em 0 .8em;padding-left:1.5em}.body li{margin:.14em 0}.body blockquote{margin:.8em 0;padding:.15em 0 .15em .9em;border-left:3px solid #98a2b3;color:#344054}.body pre{max-width:100%;margin:.8em 0;padding:10px 12px;border:1px solid var(--line);border-radius:5px;background:#f8fafc;font:.78em/1.5 "SFMono-Regular",Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}.body :not(pre)>code,.body kbd,.body samp{padding:.08em .28em;border-radius:3px;background:#f2f4f7;font:.84em "SFMono-Regular",Consolas,monospace}.body table{width:100%;margin:.9em 0;border-collapse:collapse;table-layout:fixed;font-size:.85em}.body th,.body td{padding:6px 7px;border:1px solid #98a2b3;text-align:left;vertical-align:top;overflow-wrap:anywhere}.body th{background:#f2f4f7}.body a{color:#104fbf;overflow-wrap:anywhere}.body img{display:block;max-width:100%;height:auto;margin:.9em auto}.dock{position:fixed;z-index:8;right:0;bottom:0;left:0;padding:10px max(16px,calc((100vw - 770px)/2)) 12px;border-top:1px solid var(--line);background:var(--work);box-shadow:0 -2px 8px rgba(16,24,40,.08)}.print{display:flex;align-items:center;justify-content:center;width:100%;min-height:62px;gap:12px;border:1px solid var(--blue);border-radius:7px;background:var(--blue);color:#fff;font-size:19px;font-weight:650}.print .icon{width:26px;height:26px}.print:disabled{opacity:.55}.hint{margin:10px 0 0;color:#667085;font-size:13px;text-align:center}body[data-theme=clean]{--doc:var(--ui)}body[data-theme=compact]{--doc:var(--ui)}body[data-theme=compact] .paper{font-size:13px;line-height:1.42}body[data-theme=compact] .message{margin-bottom:11px;padding-bottom:11px}@media(max-width:480px){.screen-header{padding:12px 16px}.brand{font-size:22px}.main{width:min(100% - 20px,770px);padding-top:18px}.paper{min-height:0;padding:27px 18px 36px;font-size:14.5px}.document-header h1{font-size:22px}.meta{display:grid;gap:2px}.print{min-height:58px}}@media print{@page{size:A4;margin:15mm 16mm 16mm}html,body{min-width:0;background:#fff!important}.screen-only,.status{display:none!important}.main{width:auto;padding:0}.paper{min-height:0;margin:0;padding:0;box-shadow:none}.message{break-inside:auto}.role,.body h1,.body h2,.body h3{break-after:avoid-page}.body blockquote,.body figure,.body img,.body table{break-inside:avoid-page}}
`;

  function append(parent, tag, className, text) {
    const node = parent.ownerDocument.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    parent.appendChild(node);
    return node;
  }

  function icon(parent, kind, className = "icon") {
    const doc = parent.ownerDocument;
    const svg = doc.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("class", className);
    const paths = kind === "print"
      ? ["M7 8V3h10v5", "M7 17H5a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2", "M7 14h10v7H7z"]
      : kind === "edit"
        ? ["M12 20h9", "M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4z"]
        : ["M6 2h8l4 4v16H6z", "M14 2v5h5", "M9 12h6", "M9 16h6"];
    for (const value of paths) {
      const path = doc.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("d", value);
      svg.appendChild(path);
    }
    parent.appendChild(svg);
    return svg;
  }

  function select(parent, label, values) {
    const field = append(parent, "select");
    field.setAttribute("aria-label", label);
    for (const [value, text] of values) {
      const item = field.ownerDocument.createElement("option");
      item.value = value;
      item.textContent = text;
      field.appendChild(item);
    }
    return field;
  }

  function pageWindow(doc) { return doc.defaultView || root; }

  function visible(element) {
    let current = element;
    const seen = new Set();
    while (current && current.nodeType === 1 && !seen.has(current)) {
      seen.add(current);
      if (current.hidden || current.hasAttribute("inert") || current.getAttribute("aria-hidden") === "true") return false;
      try {
        const style = pageWindow(current.ownerDocument).getComputedStyle(current);
        if (style.display === "none" || style.visibility === "hidden" || style.visibility === "collapse") return false;
      } catch (_error) { /* Keep otherwise readable content. */ }
      if (current.parentElement) current = current.parentElement;
      else {
        const scope = current.getRootNode && current.getRootNode();
        if (scope && scope.host) current = scope.host;
        else {
          try { current = current.ownerDocument.defaultView.frameElement; } catch (_error) { current = null; }
        }
      }
    }
    return true;
  }

  function scopes(doc) {
    const result = [doc];
    const seen = new Set(result);
    for (let index = 0; index < result.length; index += 1) {
      let elements = [];
      try { elements = result[index].querySelectorAll("*"); } catch (_error) { elements = []; }
      for (const element of elements) {
        if (element.shadowRoot && !seen.has(element.shadowRoot)) {
          seen.add(element.shadowRoot);
          result.push(element.shadowRoot);
        }
        if (element.tagName === "IFRAME") {
          try {
            if (element.contentDocument && !seen.has(element.contentDocument)) {
              seen.add(element.contentDocument);
              result.push(element.contentDocument);
            }
          } catch (_error) { /* Cross-origin frame. */ }
        }
      }
    }
    return result;
  }

  function queryDeep(doc, selector) {
    const result = [];
    const seen = new Set();
    for (const scope of scopes(doc)) {
      try {
        for (const node of scope.querySelectorAll(selector)) {
          if (!seen.has(node)) { seen.add(node); result.push(node); }
        }
      } catch (_error) { /* Unsupported selector. */ }
    }
    return result;
  }

  function text(element) {
    const value = typeof element.innerText === "string" ? element.innerText : element.textContent;
    return String(value || "").replace(/[\u200b-\u200d\ufeff]/gu, "").replace(/\r\n?/gu, "\n").replace(/[ \t]+\n/gu, "\n").replace(/\n{3,}/gu, "\n\n").trim();
  }

  function role(element, fixed) {
    if (fixed) return shared.normalizeRole(fixed);
    for (const name of ["data-message-author-role", "data-author-role", "data-role", "data-author", "data-speaker", "data-testid", "aria-label"]) {
      const found = shared.normalizeRole(element.getAttribute(name));
      if (found !== "unknown") return found;
    }
    const opening = text(element).slice(0, 70);
    if (/^(?:you|human|user)\s*:/iu.test(opening)) return "user";
    if (/^(?:assistant|ai|model|claude|gemini|chatgpt|copilot)\s*:/iu.test(opening)) return "assistant";
    return "unknown";
  }

  function candidates(doc, group) {
    const found = [];
    const seen = new Set();
    for (const [selector, fixed] of group.q) {
      for (const node of queryDeep(doc, selector)) {
        if (seen.has(node) || !visible(node) || !text(node)) continue;
        seen.add(node);
        found.push({ node, role: role(node, fixed), excluded: new Set() });
      }
    }
    found.sort((left, right) => {
      const position = left.node.compareDocumentPosition(right.node);
      return position & 2 ? 1 : position & 4 ? -1 : 0;
    });
    const removed = new Set();
    for (const outer of found) {
      for (const inner of found) {
        if (outer === inner || !outer.node.contains(inner.node)) continue;
        if (outer.role !== "unknown" && inner.role !== "unknown" && outer.role !== inner.role) outer.excluded.add(inner.node);
        else if (outer.role === "unknown" && inner.role !== "unknown") removed.add(outer);
        else removed.add(inner);
      }
    }
    return found.filter((item) => !removed.has(item));
  }

  function selectConversation(doc, hostname) {
    const choices = [];
    for (const site of GROUPS) {
      if (site.h.some((host) => hostname === host || hostname.endsWith(`.${host}`))) choices.push({ ...site, preferred: true });
    }
    choices.push(...GENERIC);
    let best = { score: -Infinity, items: [] };
    for (const group of choices) {
      const items = candidates(doc, group);
      const roles = new Set(items.map((item) => item.role));
      const complete = roles.has("user") && roles.has("assistant");
      if (group.low && !complete) continue;
      const score = items.length * 5 + (complete ? 150 : 0) + (group.preferred ? 80 : 0);
      if (score > best.score) best = { score, items };
    }
    return best.items;
  }

  function children(node) {
    if (node.tagName === "SLOT" && typeof node.assignedNodes === "function") {
      const assigned = node.assignedNodes({ flatten: true });
      if (assigned.length) return assigned;
    }
    return node.shadowRoot ? node.shadowRoot.childNodes : node.childNodes;
  }

  // Structured nodes are strings or [tag, attributes, children].
  function captureNode(node, options, baseUrl, excluded = new Set()) {
    if (node.nodeType === 3) return node.nodeValue || "";
    if (node.nodeType !== 1 || excluded.has(node) || !visible(node)) return null;
    const originalTag = node.tagName.toUpperCase();
    if (originalTag === "IFRAME" && options.mode === "page") {
      try {
        const frameDoc = node.contentDocument;
        const frameRoot = frameDoc && (frameDoc.querySelector("main,[role='main']") || frameDoc.body);
        if (frameRoot) return ["section", {}, Array.from(children(frameRoot), (child) => captureNode(child, options, frameDoc.location.href, excluded)).filter((item) => item !== null)];
      } catch (_error) { return node.getAttribute("title") || null; }
    }
    if (SKIP.has(originalTag)) return null;
    if (originalTag === "SVG" || originalTag === "CANVAS") return node.getAttribute("aria-label") || node.getAttribute("title") || null;
    if (originalTag === "IMG" && !options.includeImages) return node.getAttribute("alt") || null;
    const tag = (SAFE.has(originalTag) || MATH.has(originalTag)) ? originalTag.toLowerCase() : "span";
    const attrs = {};
    if (originalTag === "A") {
      const href = shared.safeUrl(node.getAttribute("href"), baseUrl, "link");
      if (href) attrs.href = href;
      const title = node.getAttribute("title");
      if (title) attrs.title = title.slice(0, 500);
    } else if (originalTag === "IMG") {
      const src = shared.safeUrl(node.currentSrc || node.getAttribute("src"), baseUrl, "image");
      if (src) attrs.src = src;
      const alt = node.getAttribute("alt");
      if (alt) attrs.alt = alt.slice(0, 1000);
    } else if (originalTag === "DETAILS" && node.hasAttribute("open")) attrs.open = "";
    else if (originalTag === "TIME" && node.hasAttribute("datetime")) attrs.datetime = node.getAttribute("datetime").slice(0, 100);
    else if (originalTag === "MATH" && node.getAttribute("display") === "block") attrs.display = "block";
    for (const name of originalTag === "OL" ? ["start", "type"] : originalTag === "LI" ? ["value"] : ["TD", "TH"].includes(originalTag) ? ["colspan", "rowspan", "scope"] : []) {
      if (node.hasAttribute(name)) attrs[name] = node.getAttribute(name).slice(0, 20);
    }
    if (originalTag === "CODE") {
      const language = Array.from(node.classList || []).find((name) => /^language-[a-z0-9_+-]+$/iu.test(name));
      if (language) attrs.class = language;
    }
    return [tag, attrs, Array.from(children(node), (child) => captureNode(child, options, baseUrl, excluded)).filter((item) => item !== null)];
  }

  function treeText(tree) {
    if (typeof tree === "string") return tree;
    if (!tree) return "";
    return tree[2].map(treeText).join(["br", "p", "div", "li", "tr", "h1", "h2", "h3", "pre"].includes(tree[0]) ? "\n" : "");
  }

  function treeHasImage(tree) {
    return Array.isArray(tree) && (tree[0] === "img" || tree[2].some(treeHasImage));
  }

  function renderNode(tree, doc) {
    if (typeof tree === "string") return doc.createTextNode(tree);
    const [tag, attrs, childTrees] = tree;
    const node = MATH.has(tag.toUpperCase()) ? doc.createElementNS("http://www.w3.org/1998/Math/MathML", tag) : doc.createElement(tag);
    if (tag === "img") {
      node.referrerPolicy = "no-referrer";
      node.loading = "eager";
      node.decoding = "async";
    }
    for (const [name, value] of Object.entries(attrs)) {
      if (name === "href") { node.href = value; node.rel = "noreferrer noopener"; node.target = "_blank"; }
      else if (name === "src") node.src = value;
      else node.setAttribute(name, value);
    }
    for (const child of childTrees) node.appendChild(renderNode(child, doc));
    return node;
  }

  function pageLocation(doc) {
    try { return new URL(pageWindow(doc).location.href); } catch (_error) { return new URL("https://unknown.invalid/"); }
  }

  function capture(doc, mode = "conversation", includeImages = false) {
    const location = pageLocation(doc);
    const options = { includeHeader: true, includeImages, mode };
    let selected = mode === "conversation" ? selectConversation(doc, location.hostname) : [];
    let fellBack = false;
    if (!selected.length) {
      fellBack = mode === "conversation";
      const rootNode = mode === "page" ? (doc.body || doc.documentElement) : (doc.querySelector("main,[role='main']") || doc.body || doc.documentElement);
      selected = [{ node: rootNode, role: "page", excluded: new Set() }];
    }
    const messages = selected.map((item) => {
      const tree = ["div", {}, Array.from(children(item.node), (child) => captureNode(child, { ...options, mode: item.role === "page" ? "page" : mode }, location.href, item.excluded)).filter((part) => part !== null)];
      return { role: item.role, label: shared.roleLabel(item.role), tree, text: treeText(tree).replace(/\n{3,}/gu, "\n\n").trim() };
    }).filter((message) => message.text || treeHasImage(message.tree));
    return {
      title: shared.deriveTitle(doc.title, location.hostname),
      source: { hostname: location.hostname || "local page", url: location.href },
      capturedAt: new Date().toISOString(), messages, options,
      diagnostics: { fellBackToPage: fellBack },
    };
  }

  function makePreview(preview) {
    const doc = preview.document;
    doc.documentElement.lang = "en";
    doc.title = "Chatprint mobile";
    const viewport = doc.createElement("meta");
    viewport.name = "viewport";
    viewport.content = "width=device-width,initial-scale=1,viewport-fit=cover";
    doc.head.appendChild(viewport);
    const style = doc.createElement("style");
    style.textContent = CSS;
    doc.head.appendChild(style);
    const header = append(doc.body, "header", "screen-header screen-only");
    const brand = append(header, "div", "brand");
    icon(brand, "document");
    append(brand, "span", "", "Chatprint");
    const back = append(header, "button", "back", "Back to chat");
    back.type = "button";
    const main = append(doc.body, "main", "main");
    const titleWrap = append(main, "div", "title-wrap screen-only");
    const titleInput = append(titleWrap, "input", "title");
    titleInput.type = "text";
    titleInput.maxLength = 180;
    titleInput.setAttribute("aria-label", "Document title");
    icon(titleWrap, "edit", "icon edit");
    const options = append(main, "details", "options screen-only");
    append(options, "summary", "", "Capture options");
    const optionsPanel = append(options, "div", "options-panel");
    const mode = select(optionsPanel, "Capture mode", [["conversation", "Conversation"], ["page", "Whole page"]]);
    const theme = select(optionsPanel, "Theme", [["classic", "Classic"], ["clean", "Clean"], ["compact", "Compact"]]);
    const images = select(optionsPanel, "Images", [["off", "Images off"], ["on", "Images on"]]);
    const status = append(main, "div", "status", "Reading the live conversation…");
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    const paper = append(main, "article", "paper");
    const documentHeader = append(paper, "header", "document-header");
    const documentTitle = append(documentHeader, "h1");
    const meta = append(documentHeader, "div", "meta");
    const sourceLink = append(meta, "a");
    sourceLink.target = "_blank";
    sourceLink.rel = "noreferrer noopener";
    const capturedDate = append(meta, "time");
    const messages = append(paper, "div");
    const dock = append(doc.body, "div", "dock screen-only");
    const print = append(dock, "button", "print");
    print.type = "button";
    print.disabled = true;
    icon(print, "print");
    append(print, "span", "", "Print / Save PDF");
    append(dock, "p", "hint", "If the print dialog does not open, use Share → Print.");
    return { back, capturedDate, documentHeader, documentTitle, images, messages, mode, paper, print, sourceLink, status, theme, titleInput };
  }

  function render(elements, result) {
    const doc = elements.messages.ownerDocument;
    const fragment = doc.createDocumentFragment();
    for (const message of result.messages) {
      const section = doc.createElement("section");
      section.className = "message";
      append(section, "h2", "role", message.label);
      const body = append(section, "div", "body");
      body.appendChild(renderNode(message.tree, doc));
      fragment.appendChild(section);
    }
    elements.messages.replaceChildren(fragment);
    elements.titleInput.value = result.title;
    elements.documentTitle.textContent = result.title;
    elements.sourceLink.textContent = result.source.hostname;
    try { elements.sourceLink.href = new URL(result.source.url).origin; } catch (_error) { elements.sourceLink.removeAttribute("href"); }
    elements.capturedDate.dateTime = result.capturedAt;
    try { elements.capturedDate.textContent = new Intl.DateTimeFormat(undefined, { dateStyle: "long" }).format(new Date(result.capturedAt)); }
    catch (_error) { elements.capturedDate.textContent = result.capturedAt.slice(0, 10); }
    elements.status.textContent = result.diagnostics.fellBackToPage ? "Conversation structure was not recognized; main page content was captured." : "";
    elements.status.hidden = !elements.status.textContent;
    elements.print.disabled = false;
  }

  function waitForImages(container) {
    const pending = Array.from(container.querySelectorAll("img")).filter((image) => !image.complete).map((image) => new Promise((resolve) => {
      image.addEventListener("load", resolve, { once: true });
      image.addEventListener("error", resolve, { once: true });
    }));
    return pending.length ? Promise.race([Promise.all(pending), new Promise((resolve) => setTimeout(resolve, 3000))]) : Promise.resolve();
  }

  function openPreview(sourceWindow, ready) {
    const preview = sourceWindow.open("about:blank", "_blank");
    if (!preview) return null;
    let finished = false;
    const finish = () => { if (!finished) { finished = true; ready(preview); } };
    const timer = sourceWindow.setTimeout(() => {
      if (finished || preview.closed) return;
      try { preview.stop(); } catch (_error) { /* Best-effort cancellation. */ }
      finish();
    }, 1200);
    try {
      const blob = new sourceWindow.Blob(["<!doctype html><html><head><meta charset=utf-8><title>Chatprint</title></head><body></body></html>"], { type: "text/html" });
      const url = sourceWindow.URL.createObjectURL(blob);
      preview.addEventListener("load", () => {
        sourceWindow.clearTimeout(timer);
        sourceWindow.URL.revokeObjectURL(url);
        finish();
      }, { once: true });
      preview.location.replace(url);
    } catch (_error) { sourceWindow.clearTimeout(timer); finish(); }
    return preview;
  }

  function run() {
    const sourceWindow = root.window === root ? root : null;
    const doc = sourceWindow && sourceWindow.document;
    if (!sourceWindow || !doc || !doc.documentElement) throw new Error("Run Chatprint from a normal web page.");
    if (!shared.isSupportedPageUrl(sourceWindow.location.href)) {
      sourceWindow.alert("Chatprint works on normal web pages, not browser settings pages.");
      return;
    }
    const old = sourceWindow.__chatprintMobileSession;
    if (old && old.preview && !old.preview.closed) {
      old.preview.focus();
      old.refresh();
      return;
    }
    // Open synchronously while the bookmark tap still counts as a user gesture.
    const preview = openPreview(sourceWindow, (target) => {
      let elements;
      try { elements = makePreview(target); }
      catch (error) { sourceWindow.alert(`Chatprint could not initialize: ${error.message || error}`); return; }
      const refresh = () => {
        elements.print.disabled = true;
        elements.status.hidden = false;
        elements.status.dataset.kind = "busy";
        elements.status.textContent = "Reading the live conversation…";
        try {
          const result = capture(doc, elements.mode.value, elements.images.value === "on");
          if (!result.messages.length) throw new Error("No printable text was found on this page.");
          render(elements, result);
          target.document.title = `${result.title} — Chatprint`;
        } catch (error) {
          elements.status.hidden = false;
          elements.status.dataset.kind = "error";
          elements.status.textContent = error.message || String(error);
        }
      };
      sourceWindow.__chatprintMobileSession = { preview: target, refresh };
      elements.back.addEventListener("click", () => sourceWindow.focus());
      elements.titleInput.addEventListener("input", () => {
        const title = elements.titleInput.value.trim() || "AI conversation";
        elements.documentTitle.textContent = title;
        target.document.title = `${title} — Chatprint`;
      });
      elements.mode.addEventListener("change", refresh);
      elements.images.addEventListener("change", refresh);
      elements.theme.addEventListener("change", () => {
        target.document.body.dataset.theme = elements.theme.value;
      });
      elements.print.addEventListener("click", async () => {
        elements.print.disabled = true;
        try { await waitForImages(elements.messages); target.focus(); target.print(); }
        finally { elements.print.disabled = false; }
      });
      target.addEventListener("beforeprint", () => {
        for (const item of target.document.querySelectorAll(".screen-only,.status")) item.hidden = true;
      });
      target.addEventListener("afterprint", () => {
        for (const item of target.document.querySelectorAll(".screen-only")) item.hidden = false;
        elements.status.hidden = !elements.status.textContent;
      });
      target.addEventListener("pagehide", () => { sourceWindow.__chatprintMobileSession = null; }, { once: true });
      try { target.opener = null; } catch (_error) { /* WindowProxy support varies. */ }
      refresh();
    });
    if (!preview) {
      sourceWindow.alert("Chatprint could not open its preview. Allow pop-ups for this site, then tap the bookmark again.");
      return;
    }
    preview.focus();
  }

  return Object.freeze({ CSS, capture, makePreview, render, renderNode, run });
});
