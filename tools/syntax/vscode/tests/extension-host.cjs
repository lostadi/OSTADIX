'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
exports.run = async function () {
  assert.ok(process.env.OSTADIX_HOST_SOURCE && process.env.OSTADIX_HOST_REPORT,
    'Set OSTADIX_HOST_SOURCE and OSTADIX_HOST_REPORT to paths inside a disposable test directory');
  const vscode = require('vscode');
  const extension = vscode.extensions.getExtension('lostadi.ostadix-lang');
  assert.ok(extension, 'Development extension must be present');
  const api = await extension.activate();
  const source = 'O^(\npython^(\ns = "before common_lisp^(\n(defun child () 42)\n)_common_lisp after"\n)_python\npython^("a )_python[*] b")_python\nbash^(\ncat <<EOF\nliteral\nEOF\n)_bash\n)_O\n';
  const uri = vscode.Uri.file(process.env.OSTADIX_HOST_SOURCE);
  fs.writeFileSync(uri.fsPath, source);
  const doc = await vscode.workspace.openTextDocument(uri);
  assert.equal(doc.languageId, 'ostadix');
  const lexical = await api.tokenize(source);
  for (const word of ['before', 'after']) {
    const index = source.indexOf(word);
    const token = lexical.find(token => token.start <= index && index < token.end);
    assert.equal(token.key, 'python');
    assert.ok(token.scopes.some(scope => scope.startsWith('string.')), word + ' must remain a Python string');
  }
  const child = lexical.find(token => token.start <= source.indexOf('defun') && source.indexOf('defun') < token.end);
  assert.equal(child.key, 'lisp');
  assert.ok(child.scopes.includes('source.commonlisp'));
  const result = await vscode.commands.executeCommand('vscode.provideDocumentSemanticTokens', uri);
  assert.ok(result && result.data.length > 0, 'Actual editor command must return semantic highlighting');
  assert.equal(result.data.length % 5, 0);
  const bOffset = source.indexOf(' b"') + 1;
  const bToken = lexical.find(token => token.start <= bOffset && bOffset < token.end);
  assert.ok(bToken.scopes.some(scope => scope.startsWith('string.')), 'Mismatched closer must remain in Python string');
  const here = lexical.find(token => token.start <= source.indexOf('literal') && source.indexOf('literal') < token.end);
  assert.ok(here.scopes.some(scope => scope.startsWith('string.')), 'Bash heredoc must receive its full grammar');
  assert.ok(api.typeFor(here), 'Dynamic heredoc scope must have a semantic type');
  await vscode.window.showTextDocument(doc);
  if (process.env.OSTADIX_HOST_HOLD) await new Promise(resolve => setTimeout(resolve, Number(process.env.OSTADIX_HOST_HOLD)));
  const next = new vscode.WorkspaceEdit();
  next.replace(uri, new vscode.Range(doc.positionAt(0), doc.positionAt(source.length)), 'O^(\ntext^(def after)_text\n)_O\n');
  await vscode.workspace.applyEdit(next);
  const changed = await vscode.commands.executeCommand('vscode.provideDocumentSemanticTokens', uri);
  assert.ok(changed && changed.data.length > 0);
  assert.notDeepEqual(Array.from(changed.data), Array.from(result.data), 'Document edit must invalidate token cache');
  const report = { editor: vscode.version, extension: extension.packageJSON.version, language: doc.languageId,
    tokens: result.data.length / 5, afterEdit: changed.data.length / 5, nestedForeignStringRestored: true, actualEditorProvider: true };
  fs.writeFileSync(process.env.OSTADIX_HOST_REPORT, JSON.stringify(report, null, 2) + '\n');
  console.log('PASS: actual VS Code extension activation, nested language grammar, semantic token API and edited-document cache');
};
