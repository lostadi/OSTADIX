(function initChatprintExtractor(root, factory) {
  const api = factory(root.ChatprintShared);
  root.ChatprintExtractor = api;
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis === "undefined" ? this : globalThis, function makeExtractor(shared) {
  "use strict";

  if (!shared) throw new Error("ChatprintShared must be loaded before the extractor.");

  const SKIPPED_TAGS = new Set([
    "BUTTON", "DIALOG", "EMBED", "IFRAME", "INPUT", "LINK", "META",
    "NOSCRIPT", "OBJECT", "OPTION", "SCRIPT", "SELECT", "STYLE", "TEMPLATE",
    "TEXTAREA",
  ]);
  const BLOCK_TAGS = new Set([
    "ADDRESS", "ARTICLE", "ASIDE", "BLOCKQUOTE", "DD", "DETAILS", "DIV", "DL",
    "DT", "FIGCAPTION", "FIGURE", "FOOTER", "FORM", "HEADER", "HGROUP", "LI", "MAIN",
    "NAV", "OL", "P", "PRE", "SECTION", "SUMMARY", "TABLE", "TBODY", "TD",
    "TFOOT", "TH", "THEAD", "TR", "UL",
  ]);
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
  const STREAMING_SELECTOR = [
    "[data-is-streaming='true']",
    "[data-testid*='stop-generating' i]",
    "button[aria-label*='stop generating' i]",
    "button[aria-label*='stop response' i]",
  ].join(",");

  const ADAPTERS = [
    {
      id: "chatgpt",
      hosts: [/(^|\.)chatgpt\.com$/iu, /(^|\.)chat\.openai\.com$/iu],
      groups: [
        {
          id: "role-attribute",
          entries: [{ selector: "[data-message-author-role]" }],
          contentSelectors: [".markdown", ".whitespace-pre-wrap"],
        },
        {
          id: "conversation-turn",
          entries: [{ selector: "article[data-testid^='conversation-turn-']" }],
          contentSelectors: ["[data-message-author-role]", ".markdown"],
        },
      ],
    },
    {
      id: "claude",
      hosts: [/(^|\.)claude\.ai$/iu],
      groups: [
        {
          id: "claude-testid",
          entries: [
            { selector: "[data-testid='user-message']", role: "user" },
            { selector: "[data-testid='assistant-message']", role: "assistant" },
            { selector: "[data-testid='model-message']", role: "assistant" },
          ],
        },
        {
          id: "claude-role",
          entries: [{ selector: "[data-message-author-role]" }],
        },
      ],
    },
    {
      id: "gemini",
      hosts: [/(^|\.)gemini\.google\.com$/iu, /(^|\.)bard\.google\.com$/iu],
      groups: [
        {
          id: "gemini-elements",
          entries: [
            { selector: "user-query", role: "user" },
            { selector: "model-response", role: "assistant" },
          ],
          contentSelectors: [".query-text", ".model-response-text", ".response-content"],
        },
      ],
    },
    {
      id: "copilot",
      hosts: [/(^|\.)copilot\.microsoft\.com$/iu, /(^|\.)bing\.com$/iu],
      groups: [
        {
          id: "copilot-content",
          entries: [
            { selector: "[data-content='user-message']", role: "user" },
            { selector: "[data-content='ai-message']", role: "assistant" },
            { selector: "[data-testid='user-message']", role: "user" },
            { selector: "[data-testid='assistant-message']", role: "assistant" },
          ],
        },
      ],
    },
    {
      id: "perplexity",
      hosts: [/(^|\.)perplexity\.ai$/iu],
      groups: [
        {
          id: "perplexity-testid",
          entries: [
            { selector: "[data-testid='user-message']", role: "user" },
            { selector: "[data-testid='answer']", role: "assistant" },
            { selector: "[data-testid='assistant-message']", role: "assistant" },
          ],
        },
      ],
    },
  ];

  const GENERIC_GROUPS = [
    {
      id: "generic-role-attribute",
      entries: [
        { selector: "[data-message-author-role]" },
        { selector: "[data-author-role]" },
      ],
    },
    {
      id: "generic-role-value",
      entries: [
        { selector: "[data-role='user'], [data-role='human']", role: "user" },
        { selector: "[data-role='assistant'], [data-role='model'], [data-role='ai']", role: "assistant" },
      ],
    },
    {
      id: "generic-custom-elements",
      entries: [
        { selector: "user-query, user-message", role: "user" },
        { selector: "model-response, assistant-message, ai-message", role: "assistant" },
      ],
    },
    {
      id: "generic-aria",
      entries: [
        { selector: "[role='article'][aria-label*='user' i], article[aria-label*='you' i]", role: "user" },
        { selector: "[role='article'][aria-label*='assistant' i], article[aria-label*='response' i]", role: "assistant" },
      ],
    },
    {
      id: "generic-articles",
      entries: [{ selector: "main article, [role='main'] article" }],
      lowConfidence: true,
    },
  ];

  function pageWindow(doc) {
    return (doc && doc.defaultView) || (typeof window === "object" ? window : null);
  }

  function pageLocation(doc) {
    const view = pageWindow(doc);
    const fallback = "https://unknown.invalid/";
    try {
      return new URL(view && view.location ? view.location.href : fallback);
    } catch (_error) {
      return new URL(fallback);
    }
  }

  function allScopes(doc) {
    const scopes = [doc];
    const visited = new Set(scopes);
    for (let index = 0; index < scopes.length; index += 1) {
      const scope = scopes[index];
      let elements = [];
      try {
        elements = scope.querySelectorAll ? scope.querySelectorAll("*") : [];
      } catch (_error) {
        elements = [];
      }
      for (const element of elements) {
        if (element.shadowRoot && !visited.has(element.shadowRoot)) {
          visited.add(element.shadowRoot);
          scopes.push(element.shadowRoot);
        }
        if (element.tagName === "IFRAME") {
          try {
            if (element.contentDocument && !visited.has(element.contentDocument)) {
              visited.add(element.contentDocument);
              scopes.push(element.contentDocument);
            }
          } catch (_error) {
            // Cross-origin frames are intentionally outside activeTab access.
          }
        }
      }
    }
    return scopes;
  }

  function queryAllDeep(doc, selector) {
    const matches = [];
    const seen = new Set();
    for (const scope of allScopes(doc)) {
      try {
        for (const element of scope.querySelectorAll(selector)) {
          if (!seen.has(element)) {
            seen.add(element);
            matches.push(element);
          }
        }
      } catch (_error) {
        // A selector unsupported by an older browser must not break generic capture.
      }
    }
    return matches;
  }

  function computedStyle(element) {
    const view = pageWindow(element.ownerDocument);
    if (!view || typeof view.getComputedStyle !== "function") return null;
    try {
      return view.getComputedStyle(element);
    } catch (_error) {
      return null;
    }
  }

  function isVisible(element) {
    if (!element || element.nodeType !== 1) return true;
    let current = element;
    const visited = new Set();
    while (current && current.nodeType === 1 && !visited.has(current)) {
      visited.add(current);
      if (current.hidden || current.hasAttribute("inert") || current.getAttribute("aria-hidden") === "true") {
        return false;
      }
      const style = computedStyle(current);
      if (style && (style.display === "none" || style.visibility === "hidden" || style.visibility === "collapse")) {
        return false;
      }
      if (current.parentElement) {
        current = current.parentElement;
      } else {
        const rootNode = typeof current.getRootNode === "function" ? current.getRootNode() : null;
        if (rootNode && rootNode.host) {
          current = rootNode.host;
        } else {
          try {
            current = current.ownerDocument
              && current.ownerDocument.defaultView
              && current.ownerDocument.defaultView.frameElement;
          } catch (_error) {
            current = null;
          }
        }
      }
    }
    return true;
  }

  function meaningfulText(node) {
    const raw = typeof node.innerText === "string" ? node.innerText : node.textContent;
    return String(raw || "")
      .replace(/[\u200b-\u200d\ufeff]/gu, "")
      .replace(/\r\n?/gu, "\n")
      .replace(/[ \t]+\n/gu, "\n")
      .replace(/\n{3,}/gu, "\n\n")
      .trim();
  }

  function accessibleFallback(element, targetDoc) {
    const label = element.getAttribute("aria-label")
      || element.getAttribute("title")
      || (element.tagName === "IMG" ? element.getAttribute("alt") : "");
    return label ? targetDoc.createTextNode(label) : targetDoc.createDocumentFragment();
  }

  function mappedTag(element) {
    const tag = element.tagName.toUpperCase();
    if (SAFE_TAGS.has(tag) || MATH_TAGS.has(tag)) return tag.toLowerCase();
    const style = computedStyle(element);
    return BLOCK_TAGS.has(tag) || (style && ["block", "flex", "grid", "list-item", "table"].includes(style.display))
      ? "div"
      : "span";
  }

  function copySafeAttributes(source, target, options, baseUrl) {
    const tag = source.tagName.toUpperCase();
    if (tag === "A") {
      const href = shared.safeUrl(source.getAttribute("href"), baseUrl, "link");
      if (href) {
        target.setAttribute("href", href);
        target.setAttribute("rel", "noreferrer noopener");
      }
      const title = source.getAttribute("title");
      if (title) target.setAttribute("title", title.slice(0, 500));
    } else if (tag === "IMG" && options.includeImages) {
      const sourceUrl = source.currentSrc || source.getAttribute("src");
      const src = shared.safeUrl(sourceUrl, baseUrl, "image");
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
    } else if (tag === "MATH" && source.hasAttribute("display")) {
      target.setAttribute("display", source.getAttribute("display") === "block" ? "block" : "inline");
    }

    if (tag === "CODE") {
      const language = Array.from(source.classList || []).find((name) => /^language-[a-z0-9_+-]+$/iu.test(name));
      if (language) target.setAttribute("class", language);
    }
  }

  function textNodeWithBreaks(value, targetDoc, context) {
    const text = String(value || "");
    if (!context.preserveLineBreaks || context.inPre || !text.includes("\n")) {
      return targetDoc.createTextNode(text);
    }
    const fragment = targetDoc.createDocumentFragment();
    const lines = text.split("\n");
    lines.forEach((line, index) => {
      if (index > 0) fragment.appendChild(targetDoc.createElement("br"));
      if (line) fragment.appendChild(targetDoc.createTextNode(line));
    });
    return fragment;
  }

  function renderedChildren(element) {
    if (element.tagName === "SLOT" && typeof element.assignedNodes === "function") {
      const assigned = element.assignedNodes({ flatten: true });
      if (assigned.length) return assigned;
    }
    if (element.shadowRoot) return element.shadowRoot.childNodes;
    return element.childNodes;
  }

  function cloneFrameContent(element, targetDoc, options, baseUrl, context) {
    const fragment = targetDoc.createDocumentFragment();
    try {
      const frameDoc = element.contentDocument;
      const frameRoot = frameDoc && (frameDoc.querySelector("main, [role='main']") || frameDoc.body);
      if (!frameRoot) return accessibleFallback(element, targetDoc);
      let frameBaseUrl = baseUrl;
      try {
        frameBaseUrl = frameDoc.location && frameDoc.location.href ? frameDoc.location.href : baseUrl;
      } catch (_error) {
        frameBaseUrl = baseUrl;
      }
      const section = targetDoc.createElement("section");
      for (const child of frameRoot.childNodes) {
        section.appendChild(cloneSafeNode(child, targetDoc, options, frameBaseUrl, context));
      }
      fragment.appendChild(section);
      return fragment;
    } catch (_error) {
      return accessibleFallback(element, targetDoc);
    }
  }

  function cloneSafeNode(node, targetDoc, options, baseUrl, context = { inPre: false, preserveLineBreaks: false }) {
    if (node.nodeType === 3) return textNodeWithBreaks(node.nodeValue, targetDoc, context);
    if (node.nodeType !== 1) return targetDoc.createDocumentFragment();

    const element = node;
    if (context.excludedNodes && context.excludedNodes.has(element)) {
      return targetDoc.createDocumentFragment();
    }
    const tag = element.tagName.toUpperCase();
    if (!isVisible(element)) return targetDoc.createDocumentFragment();
    if (tag === "IFRAME" && options.mode === "page") {
      return cloneFrameContent(element, targetDoc, options, baseUrl, context);
    }
    if (SKIPPED_TAGS.has(tag)) return targetDoc.createDocumentFragment();
    if (tag === "SVG" || tag === "CANVAS") return accessibleFallback(element, targetDoc);
    if (tag === "IMG" && !options.includeImages) return accessibleFallback(element, targetDoc);

    const tagName = mappedTag(element);
    const target = MATH_TAGS.has(tag)
      ? targetDoc.createElementNS("http://www.w3.org/1998/Math/MathML", tagName)
      : targetDoc.createElement(tagName);
    copySafeAttributes(element, target, options, baseUrl);
    const style = computedStyle(element);
    const nextContext = {
      inPre: context.inPre || tag === "PRE",
      preserveLineBreaks: context.preserveLineBreaks
        || (!context.inPre && Boolean(style && /^pre(?:-wrap|-line)?$/u.test(style.whiteSpace))),
      excludedNodes: context.excludedNodes,
    };
    for (const child of renderedChildren(element)) {
      target.appendChild(cloneSafeNode(child, targetDoc, options, baseUrl, nextContext));
    }
    return target;
  }

  function serializeContent(source, options, baseUrl, excludedNodes = new Set()) {
    const targetDoc = source.ownerDocument;
    const holder = targetDoc.createElement("div");
    const style = computedStyle(source);
    const context = {
      inPre: source.tagName === "PRE",
      preserveLineBreaks: Boolean(style && /^pre(?:-wrap|-line)?$/u.test(style.whiteSpace)),
      excludedNodes,
    };
    for (const child of renderedChildren(source)) {
      holder.appendChild(cloneSafeNode(child, targetDoc, options, baseUrl, context));
    }
    return {
      html: holder.innerHTML,
      text: meaningfulText(holder),
    };
  }

  function inferRole(element, fixedRole) {
    if (fixedRole) return shared.normalizeRole(fixedRole);
    const hints = [
      element.getAttribute("data-message-author-role"),
      element.getAttribute("data-author-role"),
      element.getAttribute("data-role"),
      element.getAttribute("data-author"),
      element.getAttribute("data-speaker"),
      element.getAttribute("data-testid"),
      element.getAttribute("aria-label"),
      element.tagName,
      typeof element.className === "string" ? element.className : "",
    ];
    for (const hint of hints) {
      const role = shared.normalizeRole(hint);
      if (role !== "unknown") return role;
    }
    const opening = meaningfulText(element).slice(0, 80);
    if (/^(?:you|you said|human|user)\s*:/iu.test(opening)) return "user";
    if (/^(?:assistant|ai|model|claude|gemini|chatgpt|copilot)\s*:/iu.test(opening)) return "assistant";
    return "unknown";
  }

  function isWithinExcludedNode(node, excludedNodes) {
    for (const excluded of excludedNodes || []) {
      if (excluded === node || excluded.contains(node)) return true;
    }
    return false;
  }

  function hasMeaningfulSiblingContent(root, boundary) {
    let current = root;
    while (current && current !== boundary) {
      const parent = current.parentNode;
      if (!parent) return false;
      for (const sibling of parent.childNodes) {
        if (sibling === current) continue;
        if (sibling.nodeType === 3 && sibling.nodeValue.trim()) return true;
        if (sibling.nodeType !== 1 || !isVisible(sibling) || SKIPPED_TAGS.has(sibling.tagName)) continue;
        if (meaningfulText(sibling) || sibling.getAttribute("alt") || sibling.getAttribute("aria-label")) {
          return true;
        }
      }
      current = parent.nodeType === 1 ? parent : null;
    }
    return false;
  }

  function contentRoot(element, selectors, excludedNodes) {
    for (const selector of selectors || []) {
      let candidates = [];
      try {
        candidates = element.querySelectorAll(selector);
      } catch (_error) {
        candidates = [];
      }
      const readable = Array.from(candidates).filter((candidate) => (
        !isWithinExcludedNode(candidate, excludedNodes) && meaningfulText(candidate)
      ));
      if (readable.length === 1 && !hasMeaningfulSiblingContent(readable[0], element)) return readable[0];
      // Multiple matching islands are safer to keep through their common message
      // container than to guess at one and silently drop the others.
      if (readable.length > 1) return element;
    }
    return element;
  }

  function documentOrder(left, right) {
    if (left === right || typeof left.compareDocumentPosition !== "function") return 0;
    const position = left.compareDocumentPosition(right);
    if (position & 2) return 1;
    if (position & 4) return -1;
    return 0;
  }

  function hasInterveningDifferentRole(outer, inner, candidates) {
    return candidates.some((middle) => (
      middle !== outer
      && middle !== inner
      && outer.node.contains(middle.node)
      && middle.node.contains(inner.node)
      && middle.role !== "unknown"
      && middle.role !== outer.role
    ));
  }

  function candidatesForGroup(doc, group) {
    const candidates = [];
    const seen = new Set();
    for (const entry of group.entries) {
      for (const node of queryAllDeep(doc, entry.selector)) {
        if (seen.has(node) || !isVisible(node)) continue;
        seen.add(node);
        const text = meaningfulText(node);
        if (!text) continue;
        candidates.push({
          node,
          role: inferRole(node, entry.role),
          contentSelectors: entry.contentSelectors || group.contentSelectors || [],
          excludedNodes: new Set(),
        });
      }
    }
    candidates.sort((left, right) => documentOrder(left.node, right.node));
    const removed = new Set();
    for (let outerIndex = 0; outerIndex < candidates.length; outerIndex += 1) {
      const outer = candidates[outerIndex];
      for (let innerIndex = outerIndex + 1; innerIndex < candidates.length; innerIndex += 1) {
        const inner = candidates[innerIndex];
        if (!outer.node.contains(inner.node)) continue;
        if (
          outer.role !== "unknown"
          && outer.role === inner.role
          && hasInterveningDifferentRole(outer, inner, candidates)
        ) {
          continue;
        }
        if (outer.role !== inner.role && outer.role !== "unknown" && inner.role !== "unknown") {
          outer.excludedNodes.add(inner.node);
          continue;
        }
        if (outer.role === "unknown" && inner.role !== "unknown") removed.add(outer);
        else removed.add(inner);
      }
    }
    return candidates.filter((candidate) => !removed.has(candidate));
  }

  function scoreCandidates(candidates, group, preferred) {
    if (!candidates.length) return -Infinity;
    const roles = new Set(candidates.map((candidate) => candidate.role).filter((role) => role !== "unknown"));
    const known = candidates.filter((candidate) => candidate.role !== "unknown").length;
    let score = candidates.length * 5 + known * 18 + roles.size * 28;
    if (roles.has("user") && roles.has("assistant")) score += 80;
    if (group.lowConfidence) score -= 70;
    if (preferred) score += 120;
    return score;
  }

  function hasConversationRoles(candidates) {
    const roles = new Set(candidates.map((candidate) => candidate.role));
    return roles.has("user") && roles.has("assistant");
  }

  function chooseCandidateGroup(doc, hostname) {
    const matching = ADAPTERS.filter((adapter) => adapter.hosts.some((pattern) => pattern.test(hostname)));
    const choices = [];
    for (const adapter of matching) {
      for (const group of adapter.groups) choices.push({ adapter: adapter.id, group, preferred: true });
    }
    for (const group of GENERIC_GROUPS) choices.push({ adapter: "generic", group, preferred: false });

    const evaluated = [];
    for (const choice of choices) {
      const candidates = candidatesForGroup(doc, choice.group);
      const score = choice.group.lowConfidence && !hasConversationRoles(candidates)
        ? -Infinity
        : scoreCandidates(candidates, choice.group, choice.preferred);
      evaluated.push({ ...choice, candidates, score });
    }
    const structured = evaluated.filter((choice) => (
      !choice.group.lowConfidence && hasConversationRoles(choice.candidates)
    ));
    const completeFallbacks = evaluated.filter((choice) => (
      choice.group.lowConfidence && hasConversationRoles(choice.candidates)
    ));
    const pool = structured.length
      ? structured
      : (completeFallbacks.length ? completeFallbacks : evaluated);
    let best = { adapter: "generic", group: GENERIC_GROUPS.at(-1), candidates: [], score: -Infinity };
    for (const choice of pool) {
      if (choice.score > best.score) best = choice;
    }
    return best;
  }

  function stableSourceId(element) {
    for (const name of ["data-message-id", "data-turn-id", "data-id"]) {
      const value = element.getAttribute(name);
      if (value && value.length <= 300) return `${name}:${value}`;
    }
    const id = element.getAttribute("id");
    return id && /[0-9a-f]{6}|message|turn/iu.test(id) ? `id:${id.slice(0, 300)}` : "";
  }

  function messageFromCandidate(candidate, options, baseUrl) {
    const source = contentRoot(candidate.node, candidate.contentSelectors, candidate.excludedNodes);
    const content = serializeContent(source, options, baseUrl, candidate.excludedNodes);
    if (!content.text && !/<img\b/iu.test(content.html)) return null;
    const role = candidate.role || "unknown";
    return {
      id: stableSourceId(candidate.node),
      role,
      label: shared.roleLabel(role),
      html: content.html,
      text: content.text,
    };
  }

  function collectSnapshot(doc, options, hostname, baseUrl) {
    const choice = chooseCandidateGroup(doc, hostname);
    let messages = choice.candidates
      .map((candidate) => messageFromCandidate(candidate, options, baseUrl))
      .filter(Boolean);
    if (choice.group.lowConfidence) {
      const roles = new Set(messages.map((message) => message.role));
      if (!roles.has("user") || !roles.has("assistant")) messages = [];
    }
    return { adapter: choice.adapter, group: choice.group.id, candidates: choice.candidates, messages };
  }

  function nearestScroller(node, doc) {
    let current = node && node.parentElement;
    while (current && current !== doc.body && current !== doc.documentElement) {
      const style = computedStyle(current);
      const overflow = style ? `${style.overflowY} ${style.overflow}` : "";
      if (/(auto|scroll)/u.test(overflow) && current.scrollHeight > current.clientHeight + 80) {
        return current;
      }
      current = current.parentElement;
    }
    const scrolling = doc.scrollingElement || doc.documentElement;
    return scrolling && scrolling.scrollHeight > scrolling.clientHeight * 1.5 ? scrolling : null;
  }

  function delay(milliseconds) {
    return new Promise((resolve) => setTimeout(resolve, milliseconds));
  }

  function mergeSnapshot(target, messages) {
    const occurrences = new Map();
    for (const message of messages) {
      const fingerprint = message.id || `${message.role}:${shared.hashText(message.text || message.html)}`;
      const occurrence = (occurrences.get(fingerprint) || 0) + 1;
      occurrences.set(fingerprint, occurrence);
      const key = `${fingerprint}#${occurrence}`;
      if (!target.has(key)) target.set(key, message);
    }
  }

  async function waitForStreaming(doc) {
    let streaming = false;
    try {
      streaming = Boolean(doc.querySelector(STREAMING_SELECTOR));
    } catch (_error) {
      streaming = false;
    }
    if (!streaming) return false;

    const deadline = Date.now() + 3000;
    while (Date.now() < deadline) {
      await delay(250);
      try {
        if (!doc.querySelector(STREAMING_SELECTOR)) return false;
      } catch (_error) {
        return true;
      }
    }
    return true;
  }

  async function collectConversation(doc, options, location) {
    const stillStreaming = await waitForStreaming(doc);
    const initial = collectSnapshot(doc, options, location.hostname, location.href);
    const firstNode = initial.messages.length > 0 && initial.candidates[0] && initial.candidates[0].node;
    const scroller = options.materializeLongChats ? nearestScroller(firstNode, doc) : null;
    const collected = new Map();
    let scrollSteps = 0;
    let hitScrollLimit = false;

    if (!scroller) {
      mergeSnapshot(collected, initial.messages);
    } else {
      const originalTop = scroller.scrollTop;
      const maxSteps = 100;
      try {
        scroller.scrollTop = 0;
        await delay(80);
        let lastTop = -1;
        while (scrollSteps < maxSteps) {
          const snapshot = collectSnapshot(doc, options, location.hostname, location.href);
          mergeSnapshot(collected, snapshot.messages);
          const height = Math.max(scroller.clientHeight || 1, 1);
          const maximum = Math.max(0, scroller.scrollHeight - height);
          const currentTop = scroller.scrollTop;
          if (currentTop >= maximum - 2 || currentTop === lastTop) break;
          lastTop = currentTop;
          scroller.scrollTop = Math.min(maximum, currentTop + Math.max(240, Math.floor(height * 0.82)));
          scrollSteps += 1;
          await delay(45);
        }
        hitScrollLimit = scrollSteps >= maxSteps;
      } finally {
        scroller.scrollTop = originalTop;
      }
    }

    return {
      messages: Array.from(collected.values()),
      adapter: initial.adapter,
      diagnostics: {
        adapterGroup: initial.group,
        hitScrollLimit,
        materializedLongChat: Boolean(scroller),
        scrollSteps,
        streaming: stillStreaming,
      },
    };
  }

  function pageRoot(doc, fullDocument) {
    if (fullDocument) return doc.body || doc.documentElement;
    return doc.querySelector("main, [role='main']") || doc.body || doc.documentElement;
  }

  function captureWholePage(doc, options, location, fullDocument = true) {
    const root = pageRoot(doc, fullDocument);
    const content = serializeContent(root, { ...options, mode: "page" }, location.href);
    return {
      adapter: "whole-page",
      messages: content.text || /<img\b/iu.test(content.html)
        ? [{ id: "whole-page", role: "page", label: "Page", ...content }]
        : [],
      diagnostics: {
        adapterGroup: fullDocument ? "whole-document" : "main-content",
        hitScrollLimit: false,
        materializedLongChat: false,
        scrollSteps: 0,
        streaming: false,
      },
    };
  }

  async function capture(rawOptions, explicitDocument) {
    const options = shared.normalizeOptions(rawOptions);
    const doc = explicitDocument || (typeof document === "object" ? document : null);
    if (!doc || !doc.documentElement) throw new Error("The page DOM is not available.");
    const location = pageLocation(doc);
    const result = options.mode === "page"
      ? captureWholePage(doc, options, location)
      : await collectConversation(doc, options, location);

    if (result.messages.length === 0 && options.mode === "conversation") {
      const fallback = captureWholePage(doc, options, location, false);
      result.messages = fallback.messages;
      result.adapter = "generic-page-fallback";
      result.diagnostics.fellBackToPage = true;
    }

    return {
      schemaVersion: 1,
      title: shared.deriveTitle(doc.title, location.hostname),
      source: {
        hostname: location.hostname || "local page",
        url: location.href,
      },
      capturedAt: new Date().toISOString(),
      mode: options.mode,
      adapter: result.adapter,
      options,
      messages: result.messages,
      diagnostics: {
        ...result.diagnostics,
        messageCount: result.messages.length,
      },
    };
  }

  return Object.freeze({
    capture,
    captureWholePage,
    chooseCandidateGroup,
    cloneSafeNode,
    collectSnapshot,
    inferRole,
    meaningfulText,
    queryAllDeep,
    serializeContent,
  });
});
