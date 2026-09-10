// The parser, not a foreign language's lexer, owns every O delimiter and splice.
// Source: crates/ostadix-api/src/{parser.rs,backend_catalog.inc.rs}.
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ident = '[A-Za-z_][A-Za-z0-9_]*';
const env = '\\[(?:[0-9]+|\\*)\\]';
const entry = `${ident}(?:=(?:(?![,={}])[!-~])+)?`;
// Visible ASCII minus commas, equals, braces; spaces/tabs only around entries.
const attrs = `\\{[ \\t]*${entry}(?:[ \\t]*,[ \\t]*${entry})*[ \\t]*\\}`;
const groups = [
  ['host', 'O|o|quote', 'host'],
  ['python', 'python|py', 'python'],
  ['javascript', 'javascript', 'javascript'],
  ['shell', 'bash|shell', 'shell'],
  ['html', 'html', 'html'],
  ['sql', 'sql', 'sql'],
  ['rust', 'rust', 'cstyle'],
  ['cpp', 'cpp', 'cstyle'],
  ['csharp', 'csharp', 'cstyle'],
  ['c', 'c', 'cstyle'],
  ['java', 'java', 'cstyle'],
  ['ruby', 'ruby', 'ruby'],
  ['lisp', 'racket|lisp|common_lisp', 'lisp'],
  ['nix', 'nix|nix_expr|nix_store', 'nix'],
  ['markdown', 'markdown|md', 'markdown'],
  ['latex', 'latex|tex', 'latex'],
  ['text', 'text|plain|nixos_test|ubuntu_vm|ubuntu|haskell|ocaml|webassembly|matlab|mathematica', 'plain']
];
const tags = groups.map(([, tags]) => tags).join('|');
const rawTag = `(?:${tags})(?:${env})?(?:${attrs})?`;
const closerAhead = `(?=\\)_(?:${tags})(?![A-Za-z0-9_]))`;
const inc = name => ({ include: `#${name}` });
const match = (regex, name) => ({ match: regex, name });
const keyword = words => match(`\\b(?:${words})\\b`, 'keyword.control');

const repository = {
  host: { patterns: [
    match('#.*$', 'comment.line.number-sign.ostadix'),
    inc('structural'),
    { match: `(let)([ \\t]+)(${ident})([ \\t]*)(=)`, captures: {
      1: { name: 'keyword.declaration.ostadix' },
      3: { name: 'variable.other.definition.ostadix' },
      5: { name: 'keyword.operator.assignment.ostadix' }
    } },
    match('(?:native_call|native_get|native_set|native_release|instantiate|realise|now|dry_activate|activate|current_system|scope|lazy|autonomous|batch|all|any|race)(?=\\()', 'support.function.builtin.ostadix'),
    match(`(?:${ident})(?=\\()`, 'entity.name.function.ostadix'),
    match('[(),]', 'punctuation.separator.ostadix')
  ] },
  structural: { patterns: [
    match(`\\\\(?:\\$|${rawTag}\\^\\(|\\)_${rawTag})`, 'constant.character.escape.ostadix'),
    match(`\\$${ident}`, 'variable.other.readwrite.splice.ostadix'),
    inc('blocks')
  ] },
  blocks: { patterns: [] },
  common: { patterns: [
    inc('structural'),
    match('\\b(?:0[xX][0-9A-Fa-f_]+|0[bB][01_]+|0[oO][0-7_]+|[0-9][0-9_]*(?:\\.[0-9_]+)?(?:[eE][+-]?[0-9_]+)?)\\b', 'constant.numeric'),
    match('\\b(?:true|false|null|None|True|False|nil)\\b', 'constant.language'),
    match('[+*/%=&|!<>?:~-]+', 'keyword.operator'),
    match('[(){}\\[\\],;.]', 'punctuation.separator')
  ] },
  plain: { patterns: [inc('structural')] }
};

// Foreign strings/comments contain O syntax too. End their lexical context before
// a closer so the outer O rule can check the *exact* opener spelling.
const region = (begin, end, name, extra = []) => ({
  begin, end: `${end}|${closerAhead}`, name,
  patterns: [inc('structural'), ...extra]
});
const escape = match('\\\\[^\\n\\\\$]', 'constant.character.escape');
const dq = region('"', '"', 'string.quoted.double', [escape]);
const sq = region("'", "'", 'string.quoted.single', [escape]);
const hash = region('#', '$', 'comment.line.number-sign');
const slash = region('//', '$', 'comment.line.double-slash');
const block = region('/\\*', '\\*/', 'comment.block');
const basic = [dq, sq, inc('common')];
repository.python = { patterns: [hash,
  region('"""', '"""', 'string.quoted.multi.python', [escape]),
  region("'''", "'''", 'string.quoted.multi.python', [escape]),
  keyword('and|as|assert|async|await|break|class|continue|def|del|elif|else|except|finally|for|from|global|if|import|in|is|lambda|nonlocal|not|or|pass|raise|return|try|while|with|yield'),
  ...basic] };
repository.javascript = { patterns: [slash, block,
  region('`', '`', 'string.template.javascript', [escape]),
  keyword('async|await|break|case|catch|class|const|continue|debugger|default|delete|do|else|export|extends|finally|for|from|function|if|import|in|instanceof|let|new|of|return|static|super|switch|throw|try|typeof|var|void|while|yield'),
  ...basic] };
repository.shell = { patterns: [hash,
  keyword('case|do|done|elif|else|esac|fi|for|function|if|in|select|then|time|until|while'),
  ...basic] };
repository.cstyle = { patterns: [slash, block,
  keyword('as|async|await|break|case|catch|class|const|continue|default|do|else|enum|extern|fn|for|if|impl|import|in|interface|let|loop|match|mod|move|mut|namespace|new|package|private|protected|pub|public|ref|return|static|struct|super|switch|template|this|throw|trait|try|type|typedef|unsafe|use|using|virtual|void|volatile|where|while'),
  ...basic] };
repository.ruby = { patterns: [hash,
  keyword('alias|and|begin|break|case|class|def|defined|do|else|elsif|end|ensure|for|if|in|module|next|not|or|redo|rescue|retry|return|self|super|then|undef|unless|until|when|while|yield'), ...basic] };
repository.sql = { patterns: [region('--', '$', 'comment.line.double-dash'), block,
  match('(?i)\\b(?:select|from|where|insert|into|values|update|delete|create|drop|table|alter|join|left|right|inner|outer|on|as|and|or|not|order|by|group|having|limit|offset|union|all|distinct|set|with|null|is)\\b', 'keyword.control.sql'),
  ...basic] };
repository.lisp = { patterns: [region(';', '$', 'comment.line.semicolon'),
  keyword('define|lambda|let|letrec|if|cond|begin|quote|quasiquote|defun|defvar|defparameter|progn|loop|when|unless'), dq, inc('common')] };
repository.nix = { patterns: [hash, block,
  keyword('assert|else|if|in|inherit|let|or|rec|then|with'), ...basic] };
repository.html = { patterns: [region('<!--', '-->', 'comment.block.html'),
  { ...region('(</?)([A-Za-z][A-Za-z0-9:-]*)', '/?>', 'meta.tag.html', [dq, sq, match('[A-Za-z_:][A-Za-z0-9_:-]*(?=\\s*=)', 'entity.other.attribute-name.html')]),
    beginCaptures: { 1: { name: 'punctuation.definition.tag.begin.html' }, 2: { name: 'entity.name.tag.html' } },
    endCaptures: { 0: { name: 'punctuation.definition.tag.end.html' } }
  },
  match('&(?:[A-Za-z][A-Za-z0-9]+|#[0-9]+|#x[0-9A-Fa-f]+);', 'constant.character.entity.html'),
  inc('structural')] };
repository.markdown = { patterns: [
  // Heading markup is a token; the remainder remains available to O splices.
  match('^#{1,6}(?=\\s)', 'markup.heading.markdown'),
  match('(?:\\*\\*|__|\\*|_|`)', 'punctuation.definition.markup.markdown'), inc('structural')] };
repository.latex = { patterns: [region('%', '$', 'comment.line.percentage.latex'),
  match('\\\\[A-Za-z]+', 'support.function.latex'), inc('structural')] };

for (const [name, alternatives, body] of groups) {
  // Three variants preserve the parser's distinct closer suffix checks.
  for (const form of ['attrs', 'env', 'bare']) {
    const suffix = form === 'attrs' ? `(${env})?(${attrs})` : form === 'env' ? `(${env})` : '';
    const guard = form === 'attrs' ? '' : form === 'env' ? '(?!\\{)' : '(?![A-Za-z0-9_\\[{])';
    const begin = `((${alternatives})${suffix})(\\^\\()`;
    const delimiterGroup = form === 'attrs' ? 5 : form === 'env' ? 4 : 3;
    const captures = {
      2: { name: 'support.type.evaluator.ostadix' },
      [delimiterGroup]: { name: 'punctuation.section.block.begin.ostadix' }
    };
    if (form !== 'bare') captures[3] = { name: 'constant.numeric.environment.ostadix' };
    if (form === 'attrs') captures[4] = { name: 'storage.modifier.attribute.ostadix' };
    repository.blocks.patterns.push({
      name: `meta.block.${name}.ostadix`,
      contentName: name === 'host' ? 'meta.sequence.ostadix' : `meta.embedded.block.${name}.ostadix`,
      begin, beginCaptures: captures,
      end: `(\\)_)(\\1)${guard}`,
      endCaptures: {
        1: { name: 'punctuation.section.block.end.ostadix' },
        2: { name: 'support.type.evaluator.ostadix' }
      },
      patterns: [inc('structural'), inc(body)]
    });
  }
}
const grammar = {
  $schema: 'https://raw.githubusercontent.com/martinring/tmlanguage/master/tmlanguage.json',
  name: 'Ostadix-lang', scopeName: 'source.ostadix',
  comment: 'Generated by ../generate.mjs. Exact O delimiters and lightweight embedded lexical rules; no language server or evaluation.',
  patterns: [inc('host')], repository
};
const output = new URL('./syntaxes/ostadix.tmLanguage.json', import.meta.url);
mkdirSync(fileURLToPath(new URL('./syntaxes/', import.meta.url)), { recursive: true });
writeFileSync(output, JSON.stringify(grammar, null, 2) + '\n');
console.log(`Generated ${fileURLToPath(output)}`);
