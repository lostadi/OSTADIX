import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
const require = createRequire(import.meta.url);
const { scan, project, tags, headerAt } = require('./scanner.cjs');
const { tokenize, createRegistry, manifest, textmate } = require('./tokenizer.cjs');
const { makeProvider, typeFor } = require('./extension.cjs');
const pkg = require('./package.json');
let checks = 0;
function ok(value, message) { assert.ok(value, message); checks++; }
function equal(actual, expected, message) { assert.deepEqual(actual, expected, message); checks++; }
async function fixture(source) {
  const tokens = await tokenize(source);
  for (let index = 1; index < tokens.length; index++) ok(tokens[index - 1].end <= tokens[index].start, 'Lexical tokens must not overlap');
  return { source, tokens };
}
function has(result, needle, scope, occurrence = 0) {
  let offset = -1; for (let index = 0; index <= occurrence; index++) offset = result.source.indexOf(needle, offset + 1);
  ok(offset >= 0, `Fixture missing ${needle}`);
  const token = result.tokens.find(token => token.start <= offset && token.end > offset);
  ok(token?.scopes.some(candidate => candidate === scope || candidate.startsWith(scope + '.')),
    `${JSON.stringify(needle)} should have ${scope}; got ${JSON.stringify(token?.scopes)}`);
}
// Exact complete header, alias, numeric spelling, attributes and suffix guards.
for (const { tag } of tags) {
  for (const suffix of ['', '[0007]', '[*]', '{ lazy,cap=fs.read }', '[7]{ lazy,cap=fs.read }']) {
    const raw = tag + suffix;
    const result = await fixture(`${raw}^(body)_${raw}\nlet next = text^(done)_text`);
    has(result, tag, 'support.type.evaluator.ostadix'); has(result, 'let', 'keyword.declaration.ostadix');
    equal(scan(result.source).frames[1].closed, true, `Exact ${raw} closer must close`);
  }
}
equal(tags.length, 36, '30 canonical tags plus6 aliases');
for (const source of [
  'python^("a )_python[*] b")_python\nlet next = text^(done)_text',
  'python^("a )_python{lazy} b")_python\nlet next = text^(done)_text',
  'python[1]^("a )_python[1]{lazy} b")_python[1]\nlet next = text^(done)_text',
  'py[0001]{ lazy }^("a )_py[1]{ lazy } b")_py[0001]{ lazy }\nlet next = text^(done)_text',
  'python{ lazy }^("a )_python{lazy} b")_python{ lazy }\nlet next = text^(done)_text',
  'py^("a )_python b")_py\nlet next = text^(done)_text']) {
  const result = await fixture(source); has(result, ' b', 'string'); has(result, 'let', 'keyword.declaration.ostadix');
}
let result = await fixture('python^(value = "before html^(\n<b>$name</b>\n)_html after"\n# before $answer after\n)_python');
has(result, 'after"', 'string'); has(result, '$name', 'variable.other.readwrite.splice.ostadix');
has(result, '$answer', 'variable.other.readwrite.splice.ostadix'); has(result, ' after\n', 'comment');
const projected = project(scan(result.source).frames[1], result.source).text;
ok(projected.includes('"before 0 after"'), 'Child newlines must not terminate the parent string');
result = await fixture('python^("unterminated )_python\nlet next = text^(done)_text');
has(result, 'let', 'keyword.declaration.ostadix');
result = await fixture('O^(# python^( hidden $x )_python )_O\nlet x = text^(done)_text\n)_O');
has(result, 'python', 'comment.line.number-sign.ostadix'); equal(scan(result.source).frames.length, 3);
result = await fixture('python^("🦊 \\$literal \\python^(literal \\)_python tail")_python');
has(result, '\\$', 'constant.character.escape.ostadix'); has(result, '\\python', 'constant.character.escape.ostadix');
has(result, '\\)_python', 'constant.character.escape.ostadix'); has(result, ' tail', 'string');
result = await fixture('xpython^(42)_python'); has(result, 'python', 'support.type.evaluator.ostadix');
result = await fixture('text{defer}^(a)_text{defer}tail'); equal(scan(result.source).frames[1].closed, true);
equal(headerAt('python[4294967294]^(',0),null); equal(headerAt('python[4294967295]^(',0),null); equal(headerAt('python[4294967296]^(',0),null);
equal(headerAt('python{bad=x=y}^(', 0), null); equal(headerAt('python{ }^(', 0), null);
// Full maintained grammars: these forms were absent from the old keyword lists.
const foreign = [
 ['python','f"hello {value!r}" # note','!r','storage.type.format.python'],
 ['javascript','const rx = /a[b]+/gi; const value = `hi ${name}`;','+','keyword.operator.quantifier.regexp'],
 ['shell','cat <<EOF\nhello\nEOF\nif true; then echo ok; fi','hello','string.unquoted.heredoc'],
 ['html','<script>const n = 1;</script><style>b { color: red; }</style>','const','storage.type.js'],
 ['sql','SELECT x FROM t -- note','SELECT','keyword.other.DML.sql'],
 ['rust','fn main() { let s = r#"hello"#; }','hello','string.quoted.double.rust'],
 ['cpp','#include <vector>\nint main() { return 0; }','include','keyword.control.directive.include.cpp'],
 ['csharp','public class X { string x = @"hi"; }','hi','string.quoted.double.cs'],
 ['c','int main(void) { return 0; }','main','entity.name.function.c'],
 ['java','public class X { String x = "hi"; }','X','entity.name.type.class.java'],
 ['ruby','value = <<~EOF\nhello\nEOF\ndef f; end','hello','string.unquoted.heredoc.ruby'],
 ['lisp','(defun f (x) #\\Space "hello") ; note','#\\Space','constant.character.escape.commonlisp'],
 ['racket','#lang racket\n(define (f x) #\\space)','#lang','keyword.other.racket'],
 ['nix',"let x = ''hello''; in { inherit x; }",'hello','string.quoted.other.nix'],
 ['markdown','# Heading\n```python\ndef f(): return 1\n```','def','storage.type.function.python'],
 ['latex','\\section{Hello} % note','section','support.function.section.latex'],
 ['haskell','module Main where\n{- note -}\nf x = if x then True else False',' note ','comment.block.haskell'],
 ['ocaml','let f x = (* note *) "hello"','hello','string.quoted.double.ocaml'],
 ['webassembly','(module (func (result i32) i32.const 42))','.const','keyword.operator.word.wat'],
 ['matlab','function y = f(x)\n% note\ny = x;\nend','f(x)','entity.name.function.matlab'],
 ['mathematica','(* note *) f[x_] := "hello"','_','keyword.operator.Blank.wolfram']
];
const legendById = new Map(require('./token-scopes.json').map(record => [record.id,record]));
for (const [key, body, needle, scope] of foreign) {
  const tag = key === 'shell' ? 'bash' : key;
  result = await fixture(`${tag}^(${body})_${tag}`); has(result, needle, scope);
  if (key === 'shell' || key === 'ruby') {
    const token = result.tokens.find(token => result.source.slice(token.start,token.end) === 'hello');
    equal(legendById.get(typeFor(token)).superType,'string','Dynamic heredoc scopes must retain string token coloring');
  }
}
for (const tag of ['ubuntu','ubuntu_vm']) { result = await fixture(`${tag}^(if true; then echo ok; fi)_${tag}`); has(result, 'if', 'keyword.control.if.shell'); }
result = await fixture('nixos_test^({ name = "hello"; })_nixos_test'); has(result, 'hello', 'string.quoted.double.nix');
result = await fixture('markdown^(```nix\nlet x = 1; in x\n```)_markdown'); has(result,'let','keyword.other.nix');
result = await fixture('cpp^(#define F(x) ((x) + 1)\nint main() { return F(1); })_cpp');
has(result,'define','keyword.control.directive.define.cpp');
ok(manifest.grammars.some(record => record.scopeName === 'source.cpp.embedded.macro'), 'C++ macros require the actual upstream fragment grammar');
ok(!manifest.scopeAliases['source.cpp.embedded.macro'], 'Full C++ cannot substitute for the maintained macro fragment');
// Registry closure is pinned and declared; dangling optional upstream includes
// are explicit, never confused with a missing required backend grammar.
const known = new Set([...manifest.grammars.map(grammar => grammar.scopeName), ...Object.keys(manifest.scopeAliases),
  ...Object.keys(manifest.scopeAdapters), 'text.plain']);
for (const [scope, includes] of Object.entries(manifest.includes)) for (const included of includes) {
  ok(known.has(included) || manifest.unresolvedOptionalIncludes.includes(included), `${scope} undeclared include ${included}`);
}
for (const record of manifest.grammars) equal(createHash('sha256').update(readFileSync(new URL(record.path,import.meta.url))).digest('hex'),record.sha256);
for (const record of require('./runtime/manifest.json')) equal(createHash('sha256').update(readFileSync(new URL(record.path,import.meta.url))).digest('hex'),record.sha256);
// Real TextMate/Oniguruma parses the generated editor/Sublime overlay too.
const registry = await createRegistry(true);
const grammar = await registry.loadGrammar('source.ostadix');
for (const {tag} of tags) {
  let state=textmate.INITIAL;
  for (const line of `${tag}[*]{defer}^(body)_${tag}[*]{defer}\nlet after = text^(done)_text`.split('\n')) state=grammar.tokenizeLine(line,state).ruleStack;
  equal(state.depth,1,`${tag} static grammar did not restore root`);
}
for (const [key, body, needle, scope] of foreign) {
  const tag=key==='shell'?'bash':key, source=`${tag}^(\n${body}\n)_${tag}\nlet after = text^(done)_text`;
  let state=textmate.INITIAL, offset=0; const tokens=[];
  for (const line of source.split('\n')) {
    const result=grammar.tokenizeLine(line,state); state=result.ruleStack;
    for (const token of result.tokens) tokens.push({start:offset+token.startIndex,end:offset+Math.min(token.endIndex,line.length),scopes:token.scopes});
    offset+=line.length+1;
  }
  has({source,tokens},needle,scope); equal(state.depth,1,`${tag} full static construct failed to restore root`);
}
{
  const source='markdown^(\n```nix\nlet x = 1; in x\n```\n)_markdown';
  let state=textmate.INITIAL,offset=0;const tokens=[];
  for (const line of source.split('\n')) {const result=grammar.tokenizeLine(line,state);state=result.ruleStack;
    for(const token of result.tokens)tokens.push({start:offset+token.startIndex,end:offset+Math.min(token.endIndex,line.length),scopes:token.scopes});offset+=line.length+1;}
  has({source,tokens},'let','keyword.other.nix');equal(state.depth,1,'Injected Nix fence must restore O root');
}
registry.dispose();
// Exercise the actual extension provider with VS Code-compatible document and
// token builder contracts; the separate extension-host test uses real VS Code.
class SemanticTokensLegend { constructor(tokenTypes,tokenModifiers) {Object.assign(this,{tokenTypes,tokenModifiers});} }
class SemanticTokensBuilder {
  constructor(legend) {this.legend=legend;this.values=[];}
  push(line,char,length,type,modifiers) {this.values.push({line,char,length,type,modifiers});}
  build() {return {data:this.values};}
}
const api={SemanticTokensLegend,SemanticTokensBuilder};
const {provider,legend}=makeProvider(api);
const source='python^("🦊 a )_python[*] b")_python\nlet x = text^(done)_text';
const document={version:1,getText:()=>source,positionAt:offset=>{const before=source.slice(0,offset).split('\n');return{line:before.length-1,character:before.at(-1).length};}};
const semantic=await provider.provideDocumentSemanticTokens(document,{isCancellationRequested:false});
ok(semantic.data.length>0); equal(await provider.provideDocumentSemanticTokens(document,{}),semantic,'Version cache must preserve tokens');
for (const token of await tokenize(source)) ok(legend.tokenTypes.includes(typeFor(token)));
equal(await provider.provideDocumentSemanticTokens(document,{isCancellationRequested:true}),null);
const canceled={...document,version:2};equal(await provider.provideDocumentSemanticTokens(canceled,{isCancellationRequested:true}),null);
equal(pkg.main,'./extension.cjs');equal(pkg.contributes.configurationDefaults['[ostadix]']['editor.semanticHighlighting.enabled'],true);
equal(pkg.contributes.languages[0].extensions,['.O','.olang']);
console.log(`PASS: ${checks} scanner, maintained grammar, scope closure and provider assertions (bundled vscode-textmate / Oniguruma).`);
