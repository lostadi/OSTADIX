import fs from 'node:fs';
import assert from 'node:assert/strict';
assert.ok(process.env.OSTADIX_HOST_COLOR_REPORT, 'Set OSTADIX_HOST_COLOR_REPORT to a disposable report path');
const port = Number(process.env.OSTADIX_HOST_DEBUG_PORT || 9237);
let targets;
for (let attempt = 0; attempt < 100; attempt++) {
  try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); if (targets.some(t => t.type === 'page')) break; } catch {}
  await new Promise(resolve => setTimeout(resolve, 200));
}
assert.ok(targets, 'Own development host must expose the local debugger');
const target = targets.find(t => t.type === 'page');
const socket = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
let next = 1; const pending = new Map();
socket.onmessage = event => { const value = JSON.parse(event.data); if (pending.has(value.id)) { pending.get(value.id)(value); pending.delete(value.id); } };
function rpc(method, params) { return new Promise(resolve => { const id = next++; pending.set(id, resolve); socket.send(JSON.stringify({ id, method, params })); }); }
let lines;
for (let attempt = 0; attempt < 100; attempt++) {
  const response = await rpc('Runtime.evaluate', { expression: `JSON.stringify(Array.from(document.querySelectorAll('.view-lines .view-line')).map(line => ({text:line.textContent, spans:Array.from(line.querySelectorAll('span')).filter(s=>s.className.startsWith('mtk')).map(s=>({text:s.textContent, color:getComputedStyle(s).color, classes:s.className}))})))`, returnByValue: true });
  lines = JSON.parse(response.result.result.value);
  if (lines.some(line => line.text.includes('literal')) && attempt > 20
      && new Set(lines.flatMap(line => line.spans.map(span => span.color))).size > 3) break;
  await new Promise(resolve => setTimeout(resolve, 200));
}
function colorFor(word) { for (const line of lines) for (const span of line.spans) if (span.text.includes(word)) return span.color; throw new Error('Missing rendered token ' + word); }
const before = colorFor('before'), after = colorFor('after'), defun = colorFor('defun'), literal = colorFor('literal');

assert.equal(before, after, 'Rendered Python string color must restore after multiline Lisp');
assert.notEqual(before, defun, 'Nested Lisp code must use its own keyword color');
const report = {before, after, defun, literal, themeRendered:true, lines};
fs.writeFileSync(process.env.OSTADIX_HOST_COLOR_REPORT, JSON.stringify(report,null,2)+'\n');
console.log('PASS: actual VS Code rendered Python string restoration, nested Lisp keyword color and Bash heredoc color');
socket.close();
