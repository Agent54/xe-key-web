#!/usr/bin/env node
// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// Hygiene gate. Fails if anything in the repository would leak where it was
// built or who built it:
//
//   - a private, carrier-grade or link-local IP address
//   - a host name that is not loopback or on the short allow list
//   - a home-folder path
//   - an e-mail address
//   - key material, a token, a hard-coded credential, or a key-like file
//   - a name from the workspace this was written in
//
//   node scripts/hygiene-check.mjs            scan the repository
//   node scripts/hygiene-check.mjs --json     machine-readable findings
//
// Patterns are built from fragments so this file passes its own scan.

import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { REPO_ROOT, SKIP_DIRS } from './lib/site.mjs';

const TEXT = /\.(html?|m?js|css|svg|json|webmanifest|md|yml|yaml|txt)$|(^|\/)(LICENSE|\.gitignore)$/i;
export const KEY_FILE = /(^|\/)(id_(rsa|ecdsa|ed25519)|.*\.(pem|key|p8|p12|pfx|jks|keystore)|\.env(\..*)?)$/i;

/** Hosts a URL in this repository may name. Loopback names are always fine. */
const ALLOWED_HOSTS = new Set(['www.w3.org', 'data.forgejo.org']); // fg-gate-allow: CI action host allowlist

const rx = (source, flags = 'g') => new RegExp(source, flags);
const OCTET = '(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)';

/** [rule, pattern, what it is] */
const RULES = [
  ['private-ip', rx(`(?<![\\d.])(?:10\\.${OCTET}|192\\.168|172\\.(?:1[6-9]|2\\d|3[01])|169\\.254|100\\.(?:6[4-9]|[7-9]\\d|1[01]\\d|12[0-7]))\\.${OCTET}\\.${OCTET}(?![\\d.])`), 'private, carrier-grade or link-local IP address'],
  ['home-path', rx('(?:/Us' + 'ers/|/ho' + 'me/|[A-Za-z]:\\\\Us' + 'ers\\\\)[A-Za-z0-9._-]+'), 'home-folder path'],
  // A key-web address is not a host: its last label names a resolver rail,
  // and one of the rails is the petname book. Those are left alone.
  ['internal-host', rx('(?<!key-web://[a-z0-9.-]*)\\b[a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.(?:inter' + 'nal|co' + 'rp|intra' + 'net|l' + 'an|loc' + 'al|ts\\.net|home\\.arpa)\\b(?!host)', 'gi'), 'internal host name'],
  ['email', rx('[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\\.[A-Za-z]{2,}[A-Za-z0-9.-]*'), 'e-mail address'],
  ['private-key', rx('-----BEGIN (?:[A-Z0-9 ]+ )?PRIV' + 'ATE KEY-----'), 'private key'],
  ['token', rx('\\b(?:AK' + 'IA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{24,})'), 'access token'],
  ['credential', rx('\\b(?:pass' + 'word|pass' + 'wd|sec' + 'ret|api[_-]?key|auth[_-]?token)\\s*[:=]\\s*[\'"][^\'"\\s$]{8,}[\'"]', 'gi'), 'hard-coded credential'],
  ['workspace-name', rx('\\b(?:anti' + 'gravity|gem' + 'ini|hel' + 'ium|gr' + 'ok|silver' + 'moon|super' + 'frame)\\b|\\bwave\\d+[a-z]?-', 'gi'), 'name from the build workspace'],
];

const URL_RULE = rx('\\b(?:https?|wss?)://([^\\s/\'"`)<>\\\\]+)', 'gi');

function hostAllowed(authority) {
  // Strip the punctuation of the sentence around it, then a port, including
  // one written as a template placeholder.
  const host = authority.replace(/[.,;]+$/, '').replace(/:(?:\d+|\$\{[^}]*\})$/, '').toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (host === '127.0.0.1' || host === '[::1]') return true;
  return ALLOWED_HOSTS.has(host);
}

/** Scans one file's text. Returns [{path, line, rule, what, excerpt}]. */
export function scanText(path, text) {
  const findings = [];
  const lineOf = (index) => text.slice(0, index).split('\n').length;
  for (const [rule, pattern, what] of RULES) {
    pattern.lastIndex = 0;
    for (let match = pattern.exec(text); match; match = pattern.exec(text)) {
      findings.push({ path, line: lineOf(match.index), rule, what, excerpt: match[0].slice(0, 60) });
    }
  }
  URL_RULE.lastIndex = 0;
  for (let match = URL_RULE.exec(text); match; match = URL_RULE.exec(text)) {
    if (!hostAllowed(match[1])) findings.push({ path, line: lineOf(match.index), rule: 'host', what: 'host name that is not loopback or allow-listed', excerpt: match[0].slice(0, 60) });
  }
  return findings.sort((a, b) => a.line - b.line);
}

/** Every file in the repository, as paths relative to its root. */
export function listRepo(root = REPO_ROOT) {
  const out = [];
  const walk = (abs) => {
    for (const name of readdirSync(abs).sort()) {
      if (SKIP_DIRS.has(name)) continue;
      const child = join(abs, name);
      const path = relative(root, child).split(sep).join('/');
      const stat = lstatSync(child);
      if (stat.isSymbolicLink()) out.push({ path, symlink: true });
      else if (stat.isDirectory()) walk(child);
      else if (stat.isFile()) out.push({ path, abs: child });
    }
  };
  walk(root);
  return out;
}

export function scanRepo(root = REPO_ROOT) {
  const files = listRepo(root);
  const findings = [];
  for (const file of files) {
    if (file.symlink) {
      findings.push({ path: file.path, line: 0, rule: 'symlink', what: 'symbolic link', excerpt: '' });
      continue;
    }
    if (KEY_FILE.test(file.path)) findings.push({ path: file.path, line: 0, rule: 'key-file', what: 'key-like file', excerpt: '' });
    if (TEXT.test(file.path)) findings.push(...scanText(file.path, readFileSync(file.abs, 'utf8')));
  }
  return { files, findings };
}

function main(argv) {
  const { files, findings } = scanRepo();
  if (argv.includes('--json')) console.log(JSON.stringify({ files: files.length, findings }, null, 2));
  else {
    for (const f of findings) console.error(`${f.path}:${f.line}  ${f.rule}  (${f.what})  ${JSON.stringify(f.excerpt)}`);
    console.log(`hygiene: ${files.length} files scanned, ${findings.length} finding${findings.length === 1 ? '' : 's'}`);
  }
  process.exitCode = findings.length === 0 && files.length > 0 ? 0 : 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main(process.argv.slice(2));
