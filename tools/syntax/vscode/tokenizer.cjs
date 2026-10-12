'use strict';
const fs = require('node:fs');
const path = require('node:path');
const textmate = require('./runtime/vscode-textmate/main.js');
const oniguruma = require('./runtime/vscode-oniguruma/main.js');
const { scan, project, languages } = require('./scanner.cjs');
const manifest = require('./vendor/manifest.json');
const byScope = new Map(manifest.grammars.map(grammar => [grammar.scopeName, grammar]));
const languageByKey = new Map(languages.map(language => [language.key, language]));
let registryPromise;
function createRegistry(adapted = false) {
  return oniguruma.loadWASM(fs.readFileSync(path.join(__dirname, 'runtime/vscode-oniguruma/onig.wasm'))).then(() => new textmate.Registry({
    onigLib: Promise.resolve({ createOnigScanner: sources => new oniguruma.OnigScanner(sources),
      createOnigString: value => new oniguruma.OnigString(value) }),
    getInjections: scope => manifest.grammars.filter(grammar => grammar.injectTo?.includes(adapted ? scope.replace(/\.ostadix-embedded$/, '') : scope))
      .map(grammar => adapted ? grammar.scopeName + '.ostadix-embedded' : grammar.scopeName),
    loadGrammar: async scope => {
      if (scope === 'source.ostadix') {
        const raw = JSON.parse(fs.readFileSync(path.join(__dirname, 'syntaxes/ostadix.tmLanguage.json'), 'utf8'));
        if (!adapted) { delete raw.injections; raw.repository.host.patterns = raw.repository.host.patterns.filter(rule => rule.include !== '#structural'); }
        return raw;
      }
      if (scope === 'text.plain' || scope === 'text.plain.ostadix-embedded') return { scopeName: scope, patterns: [] };
      const original = scope.endsWith('.ostadix-embedded') ? scope.slice(0, -'.ostadix-embedded'.length) : scope;
      const adapter = manifest.scopeAdapters?.[original];
      const canonical = adapter?.source || manifest.scopeAliases[original] || original;
      const grammar = byScope.get(canonical);
      if (!grammar) return null; // Only the explicitly inventoried optional upstream includes.
      const file = adapted ? `syntaxes/embedded/${grammar.name}.tmLanguage.json` : grammar.path;
      const raw = JSON.parse(fs.readFileSync(path.join(__dirname, file), 'utf8'));
      if (adapter && !adapted) raw.patterns = [{ include: '#' + adapter.repository }];
      if (scope !== raw.scopeName) raw.scopeName = scope;
      return raw;
    }
  }));
}
function registry() { return registryPromise ||= createRegistry(); }
// Preserve full foreign TextMate scope stacks, mapping projected spans back to
// the original document. A child O block collapses to one neutral expression;
// its newlines cannot terminate a string in the enclosing foreign body.
async function tokenize(source, cancellation) {
  const parsed = scan(source), tokens = [...parsed.structural];
  const grammarRegistry = await registry();
  for (const frame of parsed.frames) {
    if (cancellation?.isCancellationRequested) return [];
    const projection = project(frame, source);
    const scope = languageByKey.get(frame.key).textmateScope;
    const grammar = await grammarRegistry.loadGrammar(scope);
    if (!grammar) throw new Error(`Missing required O backend grammar ${scope}`);
    let state = textmate.INITIAL, offset = 0, segmentIndex = 0;
    for (const line of projection.text.split('\n')) {
      if (cancellation?.isCancellationRequested) return [];
      const result = grammar.tokenizeLine(line, state); state = result.ruleStack;
      for (const token of result.tokens) {
        const start = offset + token.startIndex, end = offset + Math.min(token.endIndex, line.length);
        while (segmentIndex < projection.segments.length && projection.segments[segmentIndex].end <= start) segmentIndex++;
        for (let index = segmentIndex; index < projection.segments.length; index++) {
          const segment = projection.segments[index];
          if (segment.start >= end) break;
          const left = Math.max(start, segment.start), right = Math.min(end, segment.end);
          if (right > left) tokens.push({ start: segment.originalStart + left - segment.start,
            end: segment.originalStart + right - segment.start, scopes: token.scopes, key: frame.key });
        }
      }
      offset += line.length + 1;
    }
  }
  tokens.sort((a, b) => a.start - b.start || a.end - b.end);
  return tokens;
}
module.exports = { tokenize, createRegistry, textmate, manifest, languageByKey };
