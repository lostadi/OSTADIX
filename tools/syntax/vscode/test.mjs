import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { existsSync, readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Prefer caller-provided test dependencies. On macOS, reuse the installed Code
// tokenizer by extracting only its two JS packages into a disposable directory.
let scratch;
function tokenizerModules() {
  const require = createRequire(import.meta.url);
  const base = process.env.OSTADIX_TEXTMATE_NODE_MODULES;
  try {
    const resolve = name => require.resolve(base ? join(base, name) : name);
    return { textmate: require(resolve('vscode-textmate')), oniguruma: require(resolve('vscode-oniguruma')),
      wasm: require.resolve(base ? join(base, 'vscode-oniguruma/release/onig.wasm') : 'vscode-oniguruma/release/onig.wasm') };
  } catch {}
  const app = process.env.VSCODE_APP_RESOURCES || '/Applications/Visual Studio Code.app/Contents/Resources/app';
  const asarPath = join(app, 'node_modules.asar');
  if (!existsSync(asarPath)) throw new Error('Install vscode-textmate and vscode-oniguruma in a temporary directory and set OSTADIX_TEXTMATE_NODE_MODULES to its node_modules, or set VSCODE_APP_RESOURCES.');
  const asar = readFileSync(asarPath);
  const header = JSON.parse(asar.subarray(16, 16 + asar.readUInt32LE(12)).toString());
  const offset = 8 + asar.readUInt32LE(4);
  scratch = mkdtempSync(join(tmpdir(), 'ostadix-tokenizer-'));
  function extract(node, relative) {
    const output = join(scratch, relative);
    if (node.files) {
      mkdirSync(output, { recursive: true });
      for (const [name, child] of Object.entries(node.files)) extract(child, join(relative, name));
    } else {
      writeFileSync(output, node.unpacked ? readFileSync(`${asarPath}.unpacked/${relative}`)
        : asar.subarray(offset + Number(node.offset), offset + Number(node.offset) + node.size));
    }
  }
  for (const name of ['vscode-textmate', 'vscode-oniguruma']) extract(header.files[name], name);
  return { textmate: require(join(scratch, 'vscode-textmate')), oniguruma: require(join(scratch, 'vscode-oniguruma')),
    wasm: join(scratch, 'vscode-oniguruma/release/onig.wasm') };
}

try {
  const { textmate, oniguruma, wasm } = tokenizerModules();
  await oniguruma.loadWASM(readFileSync(wasm));
  const raw = JSON.parse(readFileSync(new URL('./syntaxes/ostadix.tmLanguage.json', import.meta.url)));
  const registry = new textmate.Registry({
    onigLib: Promise.resolve({ createOnigScanner: sources => new oniguruma.OnigScanner(sources),
      createOnigString: value => new oniguruma.OnigString(value) }),
    loadGrammar: async scope => scope === raw.scopeName ? raw : null
  });
  const grammar = await registry.loadGrammar(raw.scopeName);
  let checks = 0;
  function tokenize(source) {
    let state = textmate.INITIAL;
    const lines = source.split('\n').map(line => {
      const result = grammar.tokenizeLine(line, state);
      state = result.ruleStack;
      return { line, tokens: result.tokens };
    });
    return { lines, state };
  }
  function has(result, line, needle, scope, occurrence = 0) {
    const item = result.lines[line];
    let offset = -1;
    for (let i = 0; i <= occurrence; i++) offset = item.line.indexOf(needle, offset + 1);
    assert.ok(offset >= 0, `Missing fixture text ${needle}`);
    const token = item.tokens.find(token => token.startIndex <= offset && token.endIndex > offset);
    assert.ok(token?.scopes.includes(scope), `${JSON.stringify(needle)} should have ${scope}; got ${JSON.stringify(token?.scopes)}`);
    checks++;
  }
  function closed(result) {
    assert.equal(result.state.depth, 1, 'Fixture should end outside every block/string/comment'); checks++;
  }
  let result = tokenize('let answer = py[7]{ lazy,cap=fs.read }^(\n__oval_result__ = 42 + $input\n)_py[7]{ lazy,cap=fs.read }\nnow($answer)');
  has(result, 0, 'let', 'keyword.declaration.ostadix');
  has(result, 0, 'py', 'support.type.evaluator.ostadix');
  has(result, 0, '[7]', 'constant.numeric.environment.ostadix');
  has(result, 0, '{ lazy', 'storage.modifier.attribute.ostadix');
  has(result, 1, '42', 'constant.numeric');
  has(result, 1, '$input', 'variable.other.readwrite.splice.ostadix');
  has(result, 3, 'now', 'support.function.builtin.ostadix'); closed(result);

  result = tokenize('python^(\nvalue = "inside html^(<b>$name</b>)_html string"\n# foreign comment still splices $answer\n)_python');
  has(result, 1, 'html', 'support.type.evaluator.ostadix');
  has(result, 1, '$name', 'variable.other.readwrite.splice.ostadix');
  has(result, 1, 'string', 'string.quoted.double');
  has(result, 2, '$answer', 'variable.other.readwrite.splice.ostadix'); closed(result);

  result = tokenize('python^( "unterminated foreign string )_python\nlet next = text^(done)_text');
  has(result, 1, 'let', 'keyword.declaration.ostadix'); closed(result);
  result = tokenize('python^(\nx = 1 )_python[*] still_body\ny = 2 )_python{lazy} still_body\n)_python');
  has(result, 1, 'still_body', 'meta.embedded.block.python.ostadix');
  has(result, 2, 'still_body', 'meta.embedded.block.python.ostadix'); closed(result);
  result = tokenize('python[1]^(x )_python[1]{lazy} still_body\n)_python[1]');
  has(result, 0, 'still_body', 'meta.embedded.block.python.ostadix'); closed(result);
  result = tokenize('text{defer}^(a)_text{defer}tail'); closed(result);
  result = tokenize('text^(\\$escaped \\python^(literal \\)_text\n)_text');
  has(result, 0, '\\$', 'constant.character.escape.ostadix');
  has(result, 0, '\\python', 'constant.character.escape.ostadix'); closed(result);
  result = tokenize('python^( \\$escaped )_python');
  has(result, 0, '\\$', 'constant.character.escape.ostadix'); closed(result);
  result = tokenize('O^(\n# python^( hidden $x )_python )_O\nlet value = quote^(\n# $hidden\ntext^(hello)_text\n)_quote\n)_O');
  has(result, 1, 'python', 'comment.line.number-sign.ostadix');
  has(result, 2, 'let', 'keyword.declaration.ostadix'); closed(result);
  result = tokenize('xpython^(42)_python');
  has(result, 0, 'python', 'support.type.evaluator.ostadix'); closed(result);
  result = tokenize('javascript^(let total = $x + 1;)_javascript\nmarkdown^(# Heading $name)_markdown');
  has(result, 0, 'let', 'keyword.control');
  has(result, 1, '$name', 'variable.other.readwrite.splice.ostadix'); closed(result);
  for (const tag of ['O', 'o', 'quote', 'python', 'py', 'javascript', 'bash', 'shell', 'html', 'sql', 'rust', 'cpp', 'csharp', 'c', 'java', 'ruby', 'racket', 'lisp', 'common_lisp', 'nix', 'nix_expr', 'nix_store', 'markdown', 'md', 'latex', 'tex', 'text', 'plain', 'nixos_test', 'ubuntu_vm', 'ubuntu', 'haskell', 'ocaml', 'webassembly', 'matlab', 'mathematica']) {
    result = tokenize(`${tag}[*]{defer,cap=project:src+host:/etc/hosts}^(body)_${tag}[*]{defer,cap=project:src+host:/etc/hosts}`);
    has(result, 0, tag, 'support.type.evaluator.ostadix'); closed(result);
  }
  const packageJson = JSON.parse(readFileSync(new URL('./package.json', import.meta.url)));
  assert.deepEqual(packageJson.contributes.languages[0].extensions, ['.O', '.olang']); checks++;
  registry.dispose();
  console.log(`PASS: ${checks} TextMate assertions (real vscode-textmate / Oniguruma).`);
} finally {
  if (scratch) rmSync(scratch, { recursive: true, force: true });
}
