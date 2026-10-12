// O delimiters are interpreted before foreign-language strings and comments.
// Offsets use JavaScript/VS Code UTF-16 units, not Rust's UTF-8 byte offsets.
'use strict';
const languages = require('./languages.json').languages;
const tags = languages.flatMap(language => language.tags.map(tag => ({ tag, key: language.key })))
  .sort((a, b) => b.tag.length - a.tag.length);
const identStart = ch => /[A-Za-z_]/.test(ch || '\0');
const identRest = ch => /[A-Za-z0-9_]/.test(ch || '\0');
function headerAt(source, start) {
  for (const { tag, key } of tags) {
    if (!source.startsWith(tag, start)) continue;
    let pos = start + tag.length;
    const tagEnd = pos;
    let envEnd = pos, attrsStart = pos;
    if (source[pos] === '[') {
      const env = /^\[(?:[0-9]+|\*)\]/.exec(source.slice(pos));
      if (!env || (env[0] !== '[*]' && BigInt(env[0].slice(1,-1)) > 4294967293n)) continue;
      pos += env[0].length; envEnd = pos;
    }
    attrsStart = pos;
    if (source[pos] === '{') {
      const end = source.indexOf('}', pos + 1);
      if (end < 0) continue;
      const body = source.slice(pos + 1, end);
      if (!body.split(',').every(entry => /^[ \t]*[A-Za-z_][A-Za-z0-9_]*(?:=[^\s,={}]+)?[ \t]*$/.test(entry)
          && [...entry].every(char => char === '\t' || (char >= ' ' && char <= '~')))) continue;
      pos = end + 1;
    }
    if (!source.startsWith('^(', pos)) continue;
    return { key, tag, start, tagEnd, envEnd, attrsStart, headerEnd: pos, end: pos + 2,
      raw: source.slice(start, pos), form: pos > attrsStart ? 'attrs' : envEnd > tagEnd ? 'env' : 'bare' };
  }
  return null;
}
function closerAt(source, pos, frame) {
  if (!frame.header || !source.startsWith(')_' + frame.header.raw, pos)) return 0;
  const end = pos + 2 + frame.header.raw.length;
  const next = source[end];
  if (frame.header.form === 'bare' && (identRest(next) || next === '[' || next === '{')) return 0;
  if (frame.header.form === 'env' && next === '{') return 0;
  return end;
}
function scan(source) {
  const root = { key: 'host', start: 0, bodyStart: 0, parts: [], children: [], end: source.length };
  const frames = [root], stack = [root], structural = [];
  const token = (start, end, scope) => { if (end > start) structural.push({ start, end, scopes: ['source.ostadix', scope] }); };
  let pos = 0, rawStart = 0;
  function flush(frame, until) { if (until > rawStart) frame.parts.push({ start: rawStart, end: until }); }
  function headerTokens(header, closing = false, offset = 0) {
    const base = closing ? offset + 2 - header.start : 0;
    if (closing) token(offset, offset + 2, 'punctuation.section.block.end.ostadix');
    token(header.start + base, header.tagEnd + base, 'support.type.evaluator.ostadix');
    token(header.tagEnd + base, header.envEnd + base, 'constant.numeric.environment.ostadix');
    token(header.attrsStart + base, header.headerEnd + base, 'storage.modifier.attribute.ostadix');
    if (!closing) token(header.headerEnd, header.end, 'punctuation.section.block.begin.ostadix');
  }
  while (pos < source.length) {
    const frame = stack[stack.length - 1];
    if (frame.key === 'host' && source[pos] === '#') {
      flush(frame, pos);
      let end = source.indexOf('\n', pos); if (end < 0) end = source.length;
      frame.parts.push({ start: pos, end, replacement: source.slice(pos, end) });
      token(pos, end, 'comment.line.number-sign.ostadix'); pos = rawStart = end; continue;
    }
    if (source[pos] === '\\') {
      let end = 0;
      if (source[pos + 1] === '$') end = pos + 2;
      else { const opener = headerAt(source, pos + 1); end = opener?.end || closerAt(source, pos + 1, frame); }
      if (end) {
        flush(frame, pos); frame.parts.push({ start: pos, end, replacement: source.slice(pos + 1, end) });
        token(pos, end, 'constant.character.escape.ostadix'); pos = rawStart = end; continue;
      }
    }
    const close = closerAt(source, pos, frame);
    if (close) {
      flush(frame, pos); frame.bodyEnd = pos; frame.end = close; frame.closed = true;
      headerTokens(frame.header, true, pos); stack.pop(); pos = rawStart = close; continue;
    }
    const header = headerAt(source, pos);
    if (header) {
      flush(frame, pos);
      const child = { key: header.key, header, start: pos, bodyStart: header.end, parts: [], children: [] };
      frame.parts.push({ child, replacement: '0' }); frame.children.push(child); frames.push(child); stack.push(child);
      headerTokens(header); pos = rawStart = header.end; continue;
    }
    if (source[pos] === '$' && identStart(source[pos + 1])) {
      let end = pos + 2; while (identRest(source[end])) end++;
      flush(frame, pos); frame.parts.push({ start: pos, end, replacement: '0' });
      token(pos, end, 'variable.other.readwrite.splice.ostadix'); pos = rawStart = end; continue;
    }
    pos++;
  }
  flush(stack[stack.length - 1], source.length);
  for (const frame of stack) { frame.bodyEnd = source.length; frame.end = source.length; }
  return { source, root, frames, structural };
}
function project(frame, source) {
  let text = ''; const segments = [];
  for (const part of frame.parts) {
    const value = part.replacement ?? source.slice(part.start, part.end);
    const start = text.length; text += value;
    if (part.replacement === undefined) segments.push({ start, end: text.length, originalStart: part.start });
  }
  return { text, segments };
}
module.exports = { languages, tags, headerAt, closerAt, scan, project };
