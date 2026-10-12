'use strict';
// VS Code's token API transports lexical TextMate classifications here. It is
// not a typechecker, language server, compiler, or evaluator.
const scopes = require('./token-scopes.json');
const { tokenize } = require('./tokenizer.cjs');
const byScope = new Map(scopes.map(scope => [scope.scope, scope.id]));
const typeIndex = new Map(scopes.map((scope, index) => [scope.id, index]));
function typeFor(token) {
  for (let index = token.scopes.length - 1; index >= 0; index--) {
    const scope = token.scopes[index];
    if (byScope.has(scope)) return byScope.get(scope);
    // Upstream rules interpolate captures into heredoc and other scope names.
    // Match their registered literal prefix, retaining the string/comment kind.
    let prefix = scope;
    while (prefix.includes('.')) {
      prefix = prefix.slice(0, prefix.lastIndexOf('.'));
      if (byScope.has(prefix)) return byScope.get(prefix);
    }
  }
  return byScope.get('text.plain');
}
function makeProvider(vscode) {
  const legend = new vscode.SemanticTokensLegend(scopes.map(scope => scope.id), []);
  const cache = new WeakMap();
  const provider = {
    async provideDocumentSemanticTokens(document, cancellation) {
      if (cancellation?.isCancellationRequested) return null;
      const current = cache.get(document);
      if (current?.version === document.version) return current.tokens;
      const version = document.version;
      const tokens = await tokenize(document.getText(), cancellation);
      if (cancellation?.isCancellationRequested || document.version !== version) return null;
      const builder = new vscode.SemanticTokensBuilder(legend);
      for (const token of tokens) {
        const start = document.positionAt(token.start), end = document.positionAt(token.end);
        // TextMate tokenization emits one line at a time; structural host
        // comments and exact O headers cannot contain newlines either.
        if (start.line !== end.line) throw new Error('Multiline lexical token violates VS Code token API');
        if (end.character > start.character) builder.push(start.line, start.character,
          end.character - start.character, typeIndex.get(typeFor(token)), 0);
      }
      const result = builder.build(); cache.set(document, { version, tokens: result });
      return result;
    }
  };
  return { legend, provider };
}
function activate(context) {
  const vscode = require('vscode');
  const { legend, provider } = makeProvider(vscode);
  context.subscriptions.push(vscode.languages.registerDocumentSemanticTokensProvider({ language: 'ostadix' }, provider, legend));
  return { tokenize, typeFor, provider, legend };
}
function deactivate() {}
module.exports = { activate, deactivate, makeProvider, typeFor };
