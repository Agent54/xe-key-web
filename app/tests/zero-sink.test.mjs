// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The zero-sink gate: the tree is clean, every rule bites, and the two
// audited uses cannot grow.
//
// Sink names are assembled from fragments so this file passes the gate too.

import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, test } from 'node:test';
import { REPO_ROOT, SCAN_ROOTS } from '../scripts/lib/site.mjs';
import { AUDITED, applyAudit, scanFile, scanPaths, scanText } from '../scripts/zero-sink-check.mjs';
import { tempDir } from './helpers.mjs';

const rules = (path, text) => scanText(path, text).map((finding) => finding.rule);

describe('this project', () => {
  const result = scanPaths();

  test('has no sinks', () => {
    assert.deepEqual(result.findings, []);
    assert.ok(result.files.length >= 40, `only ${result.files.length} files were scanned`);
  });

  test('scans the runner, the loader, every demo app, the scripts and the tests', () => {
    const scanned = result.files.map((file) => file.slice(REPO_ROOT.length + 1));
    for (const expected of [
      'runner/index.html', 'runner/app.css', 'runner/icon.svg', 'runner/src/main.js', 'runner/src/dom.js', 'runner/src/engine/swbn.js',
      'runner/loader/loader.html', 'runner/loader/loader.js', 'runner/loader/sw.js',
      'demos/shared/keyweb-client.js', 'demos/localpad/index.html', 'demos/localpad/app.js', 'demos/leakytracker/app.js', 'demos/peersync-calc/app.js',
      'scripts/serve.mjs', 'scripts/build-swbn.mjs', 'scripts/smoke-headless.mjs', 'scripts/zero-sink-check.mjs', 'tests/zero-sink.test.mjs',
    ]) assert.ok(scanned.includes(expected), `${expected} was not scanned`);
    assert.deepEqual([...SCAN_ROOTS], ['runner', 'demos', 'scripts', 'tests', '.forgejo']); // fg-gate-allow: CI workflow directory test
  });

  test('has exactly two audited uses, both in the key-origin loader', () => {
    assert.deepEqual(result.accepted.map((use) => `${use.path}:${use.rule}`).sort(), ['runner/loader/loader.js:trusted-types-policy', 'runner/loader/loader.js:worker-register']);
    assert.deepEqual(AUDITED.map((entry) => entry.count), [1, 1]);
    for (const entry of AUDITED) assert.ok(entry.why.length > 20);
  });

  test("the loader's one policy can only produce the worker's fixed URL", () => {
    const loader = readFileSync(join(REPO_ROOT, 'runner', 'loader', 'loader.js'), 'utf8');
    assert.match(loader, /createScriptURL: \(\) => WORKER_URL/);
    assert.match(loader, /const WORKER_URL = '\/__keyweb\/sw\.js';/);
    // No other policy method exists to be abused.
    assert.ok(!/create(HTML|Script)\s*:/.test(loader));
  });
});

describe('script rules', () => {
  const dot = '.';
  const cases = [
    ['inner-html', `node${dot}inner` + `HTML = text;`],
    ['outer-html', `node${dot}outer` + `HTML = text;`],
    ['insert-adjacent-html', `node${dot}insertAdjacent` + `HTML('beforeend', text);`],
    ['document-write', `document${dot}wri` + `te(text);`],
    ['document-write', `document . wri` + `teln (text);`],
    ['contextual-fragment', `range${dot}createContextual` + `Fragment(text);`],
    ['set-html', `node${dot}setHTML` + `Unsafe(text);`],
    ['dom-parser', `new DOM` + `Parser()`],
    ['dom-parser', `parser${dot}parseFrom` + `String(text, 'text/html')`],
    ['frame-markup', `frame${dot}src` + `doc = text;`],
    ['eval', ` ev` + `al(text);`],
    ['new-function', `new Func` + `tion('return 1')`],
    ['function-call', ` Func` + `tion('return 1')()`],
    ['string-timer', `setTimeout` + `('run()', 10)`],
    ['string-timer', 'setInterval' + '(`run()`, 10)'],
    ['style-attribute', `node.setAttribute('sty` + `le', 'color: red')`],
    ['handler-attribute', `node.setAttribute` + `("onclick", 'run()')`],
    ['css-text', `node.style${dot}css` + `Text = 'color: red';`],
    ['script-url', `link.href = 'java` + `script:run()';`],
    ['trusted-types-policy', `trusted` + `Types.createPolicy('default', {})`],
    ['script-element', `document.createElement('scr` + `ipt')`],
    ['worker-register', `navigator.service` + `Worker.regis` + `ter('/other.js')`],
    ['worker-url', `new Wor` + `ker(url)`],
    ['worker-url', `new SharedWor` + `ker(url)`],
    ['import-scripts', `import` + `Scripts(url)`],
    ['code-string', `frame.executeScript({ co` + `de: text })`],
  ];
  for (const [rule, text] of cases) {
    test(`${rule}: ${text.slice(0, 34)}`, () => {
      assert.ok(rules('x.js', text).includes(rule), `${rule} did not match`);
      assert.ok(rules('x.mjs', text).includes(rule));
    });
  }

  test('ordinary code is not flagged', () => {
    const fine = [
      'node.textContent = text;', 'node.append(document.createTextNode(text));', "node.setAttribute('title', text);", 'setTimeout(() => run(), 10);',
      'const evaluate = (x) => x;', 'object.evaluate(text);', 'node.style.setProperty("width", "10px");', "document.createElement('iframe')",
      'navigator.serviceWorker.ready', 'const worker = registration.active;', 'functionCall(1)', 'medieval(1)',
    ].join('\n');
    assert.deepEqual(rules('x.js', fine), []);
  });

  test('line numbers and excerpts point at the use', () => {
    const [finding] = scanText('x.js', `const a = 1;\nconst b = 2;\nnode.inner` + `HTML = a;\n`);
    assert.equal(finding.line, 3);
    assert.equal(finding.path, 'x.js');
    assert.match(finding.what, /sink/);
  });
});

describe('markup and style rules', () => {
  const markup = [
    ['inline-script', '<script>run()</script>'],
    ['script-body', '<script src="a.js">run()</script>'],
    ['style-element', '<sty' + 'le>p { color: red }</sty' + 'le>'],
    ['style-attribute', '<p sty' + 'le="color: red">x</p>'],
    ['handler-attribute', '<button onclick="run()">x</button>'],
    ['handler-attribute', '<img src="a.png" ONERROR="run()">'],
    ['frame-markup', '<iframe src' + 'doc="<p>x</p>"></iframe>'],
    ['script-url', '<a href="java' + 'script:run()">x</a>'],
    ['base-element', '<base href="/elsewhere/">'],
    ['plugin-element', '<object data="a.swf"></object>'],
    ['plugin-element', '<embed src="a.swf">'],
    ['remote-resource', '<script src="//cdn.example/a.js"></script>'],
    ['remote-resource', '<img src="ht' + 'tps://cdn.example/a.png">'],
    ['remote-resource', '<link rel="stylesheet" href="ht' + 'tp://cdn.example/a.css">'],
    ['meta-refresh', '<meta http-equiv="refresh" content="0; url=/x">'],
    ['meta-policy', '<meta http-equiv="Content-Security-Policy" content="default-src *">'],
  ];
  for (const [rule, text] of markup) {
    test(`${rule}: ${text.slice(0, 34)}`, () => {
      assert.ok(rules('x.html', text).includes(rule), `${rule} did not match`);
    });
  }

  test('SVG is held to the markup rules', () => {
    assert.ok(rules('x.svg', '<svg><script>run()</script></svg>').includes('inline-script'));
    assert.ok(rules('x.svg', '<svg onload="run()"></svg>').includes('handler-attribute'));
  });

  test('stylesheets may not run script or load from elsewhere', () => {
    assert.ok(rules('x.css', 'p { width: expres' + 'sion(alert(1)) }').includes('css-expression'));
    assert.ok(rules('x.css', '@import url("ht' + 'tps://cdn.example/a.css");').includes('remote-import'));
    assert.ok(rules('x.css', 'p { background: url(//cdn.example/a.png) }').includes('remote-url'));
    assert.deepEqual(rules('x.css', 'p { background: url(cover.png); color: var(--accent) }'), []);
  });

  test('clean markup is not flagged, and other file types are not scanned', () => {
    assert.deepEqual(rules('x.html', '<!doctype html><link rel="stylesheet" href="app.css"><script type="module" src="app.js"></script><img src="cover.png" alt="">'), []);
    assert.deepEqual(rules('x.json', '{"a": "<script>run()</script>"}'), []);
    assert.deepEqual(rules('x.md', 'node.inner' + 'HTML'), []);
  });
});

describe('audited uses', () => {
  const policy = 'trusted' + 'Types.createPolicy("p", {});';
  const register = 'navigator.service' + 'Worker.regis' + 'ter(url);';

  test('are accepted only in the named file, only at the exact count', () => {
    const once = scanFile('runner/loader/loader.js', `${policy}\n${register}\n`);
    assert.deepEqual(once.findings, []);
    assert.equal(once.accepted.length, 2);
    // One more in the same file: both become findings.
    const twice = scanFile('runner/loader/loader.js', `${policy}\n${policy}\n${register}\n`);
    assert.deepEqual(twice.findings.map((finding) => finding.rule), ['trusted-types-policy', 'trusted-types-policy']);
    assert.equal(twice.accepted.length, 1);
    // The same code anywhere else is a finding.
    for (const path of ['runner/src/main.js', 'runner/loader/sw.js', 'demos/localpad/app.js', 'runner/loader/loader.mjs', 'loader.js']) {
      assert.equal(scanFile(path, `${policy}\n${register}\n`).findings.length, 2, path);
    }
  });

  test('do not excuse any other rule in the audited file', () => {
    const result = scanFile('runner/loader/loader.js', `${policy}\n${register}\nnode.inner` + `HTML = text;\n`);
    assert.deepEqual(result.findings.map((finding) => finding.rule), ['inner-html']);
  });

  test('an exception that matches nothing is itself a finding', () => {
    const temp = tempDir();
    try {
      mkdirSync(join(temp.dir, 'runner', 'loader'), { recursive: true });
      writeFileSync(join(temp.dir, 'runner', 'loader', 'loader.js'), `${policy}\n`);
      const result = scanPaths(['runner'], temp.dir);
      assert.deepEqual(result.findings.map((finding) => `${finding.rule}:${finding.what}`), ['stale-exception:audited exception for worker-register matches nothing']);
      assert.equal(result.accepted.length, 1);
    } finally {
      temp.remove();
    }
  });

  test('a planted sink in a scanned folder fails the gate', () => {
    const temp = tempDir();
    try {
      mkdirSync(join(temp.dir, 'demos', 'evil'), { recursive: true });
      writeFileSync(join(temp.dir, 'demos', 'evil', 'app.js'), `document.body.inner` + `HTML = location.hash;\n`);
      writeFileSync(join(temp.dir, 'demos', 'evil', 'index.html'), '<p onclick="run()">x</p>\n');
      const result = scanPaths(['demos'], temp.dir);
      assert.deepEqual(result.findings.map((finding) => `${finding.path}:${finding.line}:${finding.rule}`), ['demos/evil/app.js:1:inner-html', 'demos/evil/index.html:1:handler-attribute']);
      assert.deepEqual(applyAudit([], AUDITED), { findings: [], accepted: [] });
    } finally {
      temp.remove();
    }
  });
});
