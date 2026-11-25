#!/usr/bin/env node
// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// Zero-sink gate. Fails if any file this project ships or runs has an
// HTML-string DOM sink, string-to-code evaluation, an inline script or style,
// an inline event handler, a script-URL sink, a Trusted Types escape hatch,
// or a resource the strict policy would refuse.
//
//   node scripts/zero-sink-check.mjs              scan the project
//   node scripts/zero-sink-check.mjs <path>...    scan the given files or folders
//   node scripts/zero-sink-check.mjs --json       machine-readable findings
//
// One place needs a script-URL sink: the key-origin loader has to register
// the service worker that serves a verified bundle. That is listed in
// AUDITED below with an exact count, so one more use anywhere, or one more
// in that file, fails the gate, and so does an entry that no longer matches.
//
// Every pattern is assembled from fragments, so this file passes its own
// scan and a search of the tree for a sink's name finds only real uses.

import { existsSync, lstatSync, readFileSync, readdirSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { REPO_ROOT, SCAN_ROOTS, SKIP_DIRS } from './lib/site.mjs';

const SCANNED = /\.(html?|m?js|css|svg)$/i;
const rx = (source, flags = 'g') => new RegExp(source, flags);
const Q = '[\'"`]';

/** [rule, pattern, what it is] for script files. */
const SCRIPT_RULES = [
  ['inner-html', rx('\\binner' + 'HTML\\b'), 'HTML-string sink'],
  ['outer-html', rx('\\bouter' + 'HTML\\b'), 'HTML-string sink'],
  ['insert-adjacent-html', rx('insertAdjacent' + 'HTML'), 'HTML-string sink'],
  ['document-write', rx('document\\s*\\.\\s*wri' + 'te(?:ln)?\\s*\\('), 'HTML-string sink'],
  ['contextual-fragment', rx('createContextual' + 'Fragment'), 'HTML-string sink'],
  ['set-html', rx('\\.\\s*(?:setHTML' + '(?:Unsafe)?|parseHTML' + 'Unsafe)\\s*\\('), 'HTML-string sink'],
  ['dom-parser', rx('\\bDOM' + 'Parser\\b|parseFrom' + 'String\\s*\\('), 'HTML-string parser'],
  ['frame-markup', rx('\\bsrc' + 'doc\\b'), 'HTML-string sink'],
  ['eval', rx('(?:^|[^\\w.$])ev' + 'al\\s*\\('), 'string-to-code'],
  ['new-function', rx('\\bnew\\s+Func' + 'tion\\b'), 'string-to-code'],
  ['function-call', rx('(?:^|[^\\w.$])Func' + 'tion\\s*\\('), 'string-to-code'],
  ['string-timer', rx('\\bset(?:Timeout|Interval)\\s*\\(\\s*' + Q), 'string-to-code'],
  ['style-attribute', rx('setAttribute\\s*\\(\\s*' + Q + 'sty' + 'le' + Q), 'inline style'],
  ['handler-attribute', rx('setAttribute\\s*\\(\\s*' + Q + 'on[a-z]+' + Q), 'inline event handler'],
  ['css-text', rx('\\.\\s*css' + 'Text\\s*='), 'inline style'],
  ['script-url', rx('java' + 'script\\s*:', 'gi'), 'script URL'],
  ['trusted-types-policy', rx('trusted' + 'Types\\s*\\.\\s*createPolicy'), 'Trusted Types policy'],
  ['script-element', rx('createElement\\s*\\(\\s*' + Q + 'scr' + 'ipt' + Q), 'script element built at run time'],
  ['worker-register', rx('service' + 'Worker\\s*\\.\\s*regis' + 'ter\\s*\\('), 'script-URL sink (service worker)'],
  ['worker-url', rx('\\bnew\\s+(?:Shared)?Wor' + 'ker\\s*\\('), 'script-URL sink (worker)'],
  ['import-scripts', rx('\\bimport' + 'Scripts\\s*\\('), 'script-URL sink (worker import)'],
  ['code-string', rx('executeScript\\s*\\(\\s*\\{\\s*co' + 'de\\s*:'), 'code string injected into a guest'],
];

/** For markup (HTML and SVG). */
const MARKUP_RULES = [
  ['inline-script', rx('<script(?![^>]*\\ssrc\\s*=)[^>]*>', 'gi'), 'script element without src'],
  ['script-body', rx('<script[^>]*>[^<]*\\S[^<]*</script>', 'gi'), 'script element with a body'],
  ['style-element', rx('<sty' + 'le[\\s>]', 'gi'), 'inline style element'],
  ['style-attribute', rx('<[^>]*\\ssty' + 'le\\s*=', 'gi'), 'inline style attribute'],
  ['handler-attribute', rx('<[^>]*\\son[a-z]+\\s*=', 'gi'), 'inline event handler'],
  ['frame-markup', rx('\\ssrc' + 'doc\\s*=', 'gi'), 'HTML-string sink'],
  ['script-url', rx('java' + 'script\\s*:', 'gi'), 'script URL'],
  ['base-element', rx('<base[\\s>]', 'gi'), 'base element'],
  ['plugin-element', rx('<(?:object|embed|applet)[\\s>]', 'gi'), 'plugin element'],
  ['remote-resource', rx('<(?:script|link|img|iframe|audio|video|source|use|image)[^>]*\\s(?:src|href|xlink:href)\\s*=\\s*' + Q + '(?:https?:)?//', 'gi'), 'remote resource'],
  ['meta-refresh', rx('<meta[^>]*http-equiv\\s*=\\s*' + Q + '?refresh', 'gi'), 'meta refresh'],
  ['meta-policy', rx('<meta[^>]*http-equiv\\s*=\\s*' + Q + '?content-security-policy', 'gi'), 'policy in markup (it belongs in the response header)'],
];

const STYLE_RULES = [
  ['css-expression', rx('expres' + 'sion\\s*\\(', 'gi'), 'script in CSS'],
  ['script-url', rx('java' + 'script\\s*:', 'gi'), 'script URL'],
  ['remote-import', rx('@import\\s+(?:url\\()?\\s*' + Q + '?(?:https?:)?//', 'gi'), 'remote stylesheet'],
  ['remote-url', rx('url\\(\\s*' + Q + '?(?:https?:)?//', 'gi'), 'remote resource'],
];

/**
 * The audited exceptions: [repo path, rule, exact count, why]. The loader
 * creates one Trusted Types policy whose only method returns the service
 * worker's fixed URL, and passes that to one registration call.
 */
export const AUDITED = Object.freeze([
  Object.freeze({ path: 'runner/loader/loader.js', rule: 'trusted-types-policy', count: 1, why: 'one named policy that can only produce the fixed service worker URL' }),
  Object.freeze({ path: 'runner/loader/loader.js', rule: 'worker-register', count: 1, why: 'installs the worker that serves the verified bundle' }),
]);

function rulesFor(path) {
  if (/\.(html?|svg)$/i.test(path)) return MARKUP_RULES;
  if (/\.m?js$/i.test(path)) return SCRIPT_RULES;
  if (/\.css$/i.test(path)) return STYLE_RULES;
  return [];
}

/** Scans one file's text. Returns every match as [{path, line, rule, what, excerpt}], audited or not. */
export function scanText(path, text) {
  const findings = [];
  for (const [rule, pattern, what] of rulesFor(path)) {
    pattern.lastIndex = 0;
    for (let match = pattern.exec(text); match; match = pattern.exec(text)) {
      const line = text.slice(0, match.index).split('\n').length;
      findings.push({ path, line, rule, what, excerpt: match[0].trim().slice(0, 80) });
      if (match[0].length === 0) pattern.lastIndex += 1;
    }
  }
  return findings.sort((a, b) => a.line - b.line);
}

/**
 * Splits matches into findings and audited uses. An exception only applies
 * when the number of matches in its file is exactly its count.
 */
export function applyAudit(matches, audited = AUDITED) {
  const findings = [];
  const accepted = [];
  const groups = new Map();
  for (const match of matches) {
    const key = `${match.path}\n${match.rule}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(match);
  }
  for (const [key, group] of groups) {
    const [path, rule] = key.split('\n');
    const exception = audited.find((entry) => entry.path === path && entry.rule === rule);
    if (exception && group.length === exception.count) accepted.push(...group.map((match) => ({ ...match, why: exception.why })));
    else findings.push(...group);
  }
  return { findings: findings.sort((a, b) => (a.path === b.path ? a.line - b.line : a.path < b.path ? -1 : 1)), accepted };
}

/** Scans one file by its repository path. Returns {findings, accepted}. */
export function scanFile(repoPath, text) {
  return applyAudit(scanText(repoPath, text));
}

/** Every scannable file under `target` (a file or a folder), sorted. Symlinks are not followed. */
export function listFiles(target) {
  const out = [];
  if (!existsSync(target)) return out;
  const walk = (abs) => {
    const stat = lstatSync(abs);
    if (stat.isSymbolicLink()) return;
    if (stat.isDirectory()) {
      for (const name of readdirSync(abs).sort()) if (!SKIP_DIRS.has(name)) walk(join(abs, name));
    } else if (stat.isFile() && SCANNED.test(abs)) {
      out.push(abs);
    }
  };
  walk(target);
  return out;
}

export function scanPaths(targets = SCAN_ROOTS, root = REPO_ROOT, audited = AUDITED) {
  const files = targets.flatMap((target) => listFiles(resolve(root, target)));
  const matches = [];
  for (const file of files) matches.push(...scanText(relative(root, file).split(sep).join('/'), readFileSync(file, 'utf8')));
  const { findings, accepted } = applyAudit(matches, audited);
  // An exception nothing matches any more is stale, and stale exceptions are how gates rot.
  const scanned = new Set(files.map((file) => relative(root, file).split(sep).join('/')));
  for (const entry of audited) {
    if (scanned.has(entry.path) && !accepted.some((match) => match.path === entry.path && match.rule === entry.rule)
      && !findings.some((match) => match.path === entry.path && match.rule === entry.rule)) {
      findings.push({ path: entry.path, line: 0, rule: 'stale-exception', what: `audited exception for ${entry.rule} matches nothing`, excerpt: '' });
    }
  }
  return { files, findings, accepted };
}

function main(argv) {
  const json = argv.includes('--json');
  const targets = argv.filter((arg) => !arg.startsWith('--'));
  const { files, findings, accepted } = scanPaths(targets.length ? targets : SCAN_ROOTS);
  if (json) console.log(JSON.stringify({ files: files.length, findings, accepted }, null, 2));
  else {
    for (const f of findings) console.error(`${f.path}:${f.line}  ${f.rule}  (${f.what})  ${JSON.stringify(f.excerpt)}`);
    for (const a of accepted) console.log(`audited   ${a.path}:${a.line}  ${a.rule}  (${a.why})`);
    console.log(`zero-sink: ${files.length} files scanned, ${findings.length} finding${findings.length === 1 ? '' : 's'}, ${accepted.length} audited use${accepted.length === 1 ? '' : 's'}`);
  }
  process.exitCode = findings.length === 0 && files.length > 0 ? 0 : 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main(process.argv.slice(2));
