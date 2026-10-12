// Generate offline TextMate assets and lexical token metadata from pinned inputs.
import { mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
const read = path => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'));
const write = (path, value) => writeFileSync(new URL(path, import.meta.url), JSON.stringify(value, null, 2) + '\n');
const languages = read('../languages.json'); write('./languages.json', languages);
const manifest = read('./vendor/manifest.json');
const ident = '[A-Za-z_][A-Za-z0-9_]*', env = '\\[(?:[0-9]+|\\*)\\]';
const entry = `${ident}(?:=(?:(?![,={}])[!-~])+)?`;
const attrs = `\\{[ \\t]*${entry}(?:[ \\t]*,[ \\t]*${entry})*[ \\t]*\\}`;
const alternatives = languages.languages.flatMap(language => language.tags).sort((a,b) => b.length-a.length).join('|');
const rawTag = `(?:${alternatives})(?:${env})?(?:${attrs})?`;
const critical = `\\\\(?:\\$|${rawTag}\\^\\(|\\)_${rawTag})|\\$${ident}|${rawTag}\\^\\(`;
const closerAhead = `(?=\\)_(?:${alternatives})(?![A-Za-z0-9_]))`;
const embeddedScope = scope => `${scope}.ostadix-embedded`;
const inc = name => ({ include: `#${name}` });
const match = (pattern, name) => ({ match: pattern, name });
const repository = {
  host: { patterns: [match('#.*$', 'comment.line.number-sign.ostadix'), inc('structural'),
    { match: `(let)([ \\t]+)(${ident})([ \\t]*)(=)`, captures: {
      1: { name: 'keyword.declaration.ostadix' }, 3: { name: 'variable.other.definition.ostadix' },
      5: { name: 'keyword.operator.assignment.ostadix' } } },
    match('(?:native_call|native_get|native_set|native_release|instantiate|realise|now|dry_activate|activate|current_system|scope|lazy|autonomous|batch|all|any|race)(?=\\()', 'support.function.builtin.ostadix'),
    match(`${ident}(?=\\()`, 'entity.name.function.ostadix'), match('[(),]', 'punctuation.separator.ostadix')] },
  structural: { patterns: [match(`\\\\(?:\\$|${rawTag}\\^\\(|\\)_${rawTag})`, 'constant.character.escape.ostadix'),
    match(`\\$${ident}`, 'variable.other.readwrite.splice.ostadix'), inc('blocks')] },
  blocks: { patterns: [] }
};
for (const language of languages.languages) {
  for (const form of ['attrs','env','bare']) {
    const suffix = form === 'attrs' ? `(${env})?(${attrs})` : form === 'env' ? `(${env})` : '';
    const guard = form === 'attrs' ? '' : form === 'env' ? '(?!\\{)' : '(?![A-Za-z0-9_\\[{])';
    const delimiter = form === 'attrs' ? 5 : form === 'env' ? 4 : 3;
    const captures = { 2: { name: 'support.type.evaluator.ostadix' },
      [delimiter]: { name: 'punctuation.section.block.begin.ostadix' } };
    if (form !== 'bare') captures[3] = { name: 'constant.numeric.environment.ostadix' };
    if (form === 'attrs') captures[4] = { name: 'storage.modifier.attribute.ostadix' };
    repository.blocks.patterns.push({ name: `meta.block.${language.key}.ostadix`,
      contentName: language.key === 'host' ? 'meta.sequence.ostadix' : `meta.embedded.block.${language.key}.ostadix`,
      begin: `((${language.tags.join('|')})${suffix})(\\^\\()`, beginCaptures: captures,
      end: `(\\)_)(\\1)${guard}`, endCaptures: {
        1: { name: 'punctuation.section.block.end.ostadix' }, 2: { name: 'support.type.evaluator.ostadix' } },
      patterns: language.key === 'host' ? [inc('host')] : [inc('structural'),
        ...(language.key === 'text' ? [] : [{ include: embeddedScope(language.textmateScope) }])] });
  }
}
const main = { name: 'Ostadix-lang', scopeName: 'source.ostadix',
  comment: 'Generated full foreign TextMate grammar overlay. VS Code lexical token provider preserves exact O ancestor context across foreign strings/comments.',
  patterns: [inc('host')], repository };
rmSync(new URL('./syntaxes/embedded/', import.meta.url), {recursive:true, force:true});
mkdirSync(new URL('./syntaxes/embedded/', import.meta.url), { recursive: true });
function adaptedInjectionSelector(selector) {
  for (const language of languages.languages) if (language.key !== 'host') selector = selector.split(language.textmateScope).join(`meta.embedded.block.${language.key}.ostadix`);
  return selector;
}
main.injections = {};
for (const record of manifest.grammars.filter(record => record.injectTo?.length)) {
  const raw = read(record.path);
  if (raw.injectionSelector) main.injections[adaptedInjectionSelector(raw.injectionSelector)] = {patterns:[{include:embeddedScope(record.scopeName)}]};
}
write('./syntaxes/ostadix.tmLanguage.json', main);
const scopeNames = new Set(['source.ostadix','text.plain','string','comment','constant.numeric','keyword','variable','markup']);
function collect(value) {
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if ((key === 'name' || key === 'contentName') && typeof child === 'string') {
      for (let scope of child.split(' ')) {
        if (scope.includes('$')) scope = scope.slice(0, scope.indexOf('$')).replace(/\.$/, '');
        if (scope) scopeNames.add(scope);
      }
    } else if (child && typeof child === 'object') collect(child);
  }
}
collect(main);
const byScope = new Map(manifest.grammars.map(grammar => [grammar.scopeName, grammar]));
function adapt(value) {
  if (!value || typeof value !== 'object') return;
  if (typeof value.include === 'string' && !/^[#$]/.test(value.include)) {
    const [scope, fragment] = value.include.split('#');
    value.include = embeddedScope(scope) + (fragment ? `#${fragment}` : '');
  }
  for (const property of ['match','begin']) if (typeof value[property] === 'string') value[property] = `(?~|${critical}|${value[property]})`;
  if (typeof value.end === 'string') value.end = `${closerAhead}|(?:${value.end})`;
  if (typeof value.while === 'string') {
    // TextMate while contexts cannot exit midway through a line. The static
    // overlay keeps their line condition and adds an O boundary; the exact
    // provider tokenizes the untouched upstream while grammar.
    value.end = `${closerAhead}|^(?!${value.while})`;
    delete value.while; delete value.whileCaptures;
  }
  if (value.begin) {
    value.patterns ||= [];
    value.patterns.unshift({ include: 'source.ostadix#structural' });
  } else if (Array.isArray(value.patterns)) value.patterns.unshift({ include: 'source.ostadix#structural' });
  for (const child of Object.values(value)) {
    if (Array.isArray(child)) { for (const rule of child) if (rule.include !== 'source.ostadix#structural') adapt(rule); }
    else if (child && typeof child === 'object') adapt(child);
  }
}
const grammarEntries = [{ language: 'ostadix', scopeName: main.scopeName, path: './syntaxes/ostadix.tmLanguage.json',
  embeddedLanguages: Object.fromEntries(languages.languages.filter(language => language.key !== 'host')
    .map(language => [`meta.embedded.block.${language.key}.ostadix`, language.vscodeLanguage])) }];
for (const record of manifest.grammars) {
  const bytes = readFileSync(new URL(record.path, import.meta.url));
  if (createHash('sha256').update(bytes).digest('hex') !== record.sha256) throw new Error(`Pinned grammar changed: ${record.path}`);
  const raw = JSON.parse(bytes); collect(raw); scopeNames.add(raw.scopeName);
  adapt(raw); raw.scopeName = embeddedScope(record.scopeName);
  if (raw.injectionSelector) raw.injectionSelector = adaptedInjectionSelector(raw.injectionSelector);
  const path = `./syntaxes/embedded/${record.name}.tmLanguage.json`; write(path, raw);
  grammarEntries.push({ scopeName: raw.scopeName, path, ...(record.injectTo?.length ? {injectTo:record.injectTo.map(embeddedScope)} : {}) });
}
for (const [alias, scope] of Object.entries(manifest.scopeAliases)) {
  const record = byScope.get(scope);
  if (!record) throw new Error(`Missing scope alias target ${scope}`);
  const raw = read(`./syntaxes/embedded/${record.name}.tmLanguage.json`); raw.scopeName = embeddedScope(alias);
  const path = `./syntaxes/embedded/alias-${alias}.tmLanguage.json`; write(path, raw);
  grammarEntries.push({ scopeName: raw.scopeName, path });
}
for (const [scope, adapter] of Object.entries(manifest.scopeAdapters || {})) {
  const record = byScope.get(adapter.source);
  const raw = read(`./syntaxes/embedded/${record.name}.tmLanguage.json`);
  raw.scopeName = embeddedScope(scope); raw.patterns = [{ include: 'source.ostadix#structural' }, { include: '#' + adapter.repository }];
  const path = `./syntaxes/embedded/adapter-${scope}.tmLanguage.json`; write(path, raw);
  grammarEntries.push({ scopeName: raw.scopeName, path });
}
write('./syntaxes/embedded/plain.tmLanguage.json', { scopeName: embeddedScope('text.plain'), patterns: [{include: 'source.ostadix#structural'}] });
grammarEntries.push({ scopeName: embeddedScope('text.plain'), path: './syntaxes/embedded/plain.tmLanguage.json' });
const fallback = scope => {
  if (/comment/.test(scope)) return 'comment';
  if (/string|regexp/.test(scope)) return 'string';
  if (/constant.numeric/.test(scope)) return 'number';
  if (/keyword/.test(scope)) return 'keyword';
  if (/storage|support.type|entity.name.type|entity.name.class/.test(scope)) return 'type';
  if (/entity.name.function|support.function/.test(scope)) return 'function';
  if (/variable|entity.other.attribute/.test(scope)) return 'variable';
  if (/constant/.test(scope)) return 'enumMember';
  return undefined;
};
const legend = [...scopeNames].sort().map(scope => ({ scope,
  id: `o${createHash('sha256').update(scope).digest('hex').slice(0,16)}`, superType: fallback(scope) }));
write('./token-scopes.json', legend);
const pkg = read('./package.json'); pkg.version = '0.2.0'; pkg.main = './extension.cjs';
pkg.activationEvents = ['onLanguage:ostadix']; pkg.contributes.grammars = grammarEntries;
pkg.contributes.configurationDefaults = { '[ostadix]': { 'editor.semanticHighlighting.enabled': true } };
pkg.contributes.semanticTokenTypes = legend.map(({ scope,id,superType }) => ({ id,
  description: `Lexical TextMate scope: ${scope}`, ...(superType ? { superType } : {}) }));
pkg.contributes.semanticTokenScopes = [{ language: 'ostadix', scopes: Object.fromEntries(legend.map(({scope,id}) => [id,[scope]])) }];
write('./package.json', pkg);
console.log(`Generated ${grammarEntries.length} full TextMate assets and ${legend.length} lexical token scopes.`);
