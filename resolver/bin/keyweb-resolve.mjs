#!/usr/bin/env node
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 The Key-Origin Web Authors.
//
// keyweb-resolve: resolve key-web:// name URLs to canonical key URLs.
// Exit codes: 0 ok, 1 usage, 2 unresolvable, 3 FAIL-CLOSED refusal,
//             4 succession proof needs confirmation.

import fs from 'node:fs';
import process from 'node:process';
import {
  KeyWebResolver, TrustStore, MockRail, LocalRail, createLiveRails, parseKeyWebUrl,
  pinFor, parseKwId, inspectRecord, base64url, fingerprint,
} from '../src/index.mjs';
import { runDemo } from './demo.mjs';

const USAGE = `keyweb-resolve: multi-rail key-web:// resolver

Usage:
  keyweb-resolve resolve <url> [--fixtures <file> | --live] [--store <file>]
                               [--book <file>] [--no-cross-check]
                               [--accept-succession] [--json]
  keyweb-resolve parse <url> [--json]
  keyweb-resolve pin <kw-id> [--length <16..52>]
  keyweb-resolve inspect <base64url-record>
  keyweb-resolve demo [--json]

URLs:
  key-web://<kw-id>.key/                    self-certifying key URL
  key-web://<slug>.<atproto-handle>/        rail "at" (default)
  key-web://<slug>.<pkarr-key|alias>.dht/   rail "dht" (PKARR / BEP-44)
  key-web://<slug>.<npub|nip05|alias>.nostr/
  key-web://<slug>.<petname>.local/         your own publisher book
  key-web://<slug>.<publisher-kw-id>.key/
  Append #:~:pin=<16+ base32 chars> (or #pin=...) for a verified first click.

Live rails read: KEYWEB_PKARR_RELAYS, KEYWEB_NOSTR_RELAYS (comma-separated),
KEYWEB_PLC_DIRECTORY, KEYWEB_AT_NSID.

Exit codes: 0 ok, 1 usage, 2 unresolvable, 3 fail-closed refusal,
            4 succession needs confirmation.`;

function parseArgs(argv) {
  const args = { _: [], flags: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      if (['json', 'live', 'no-cross-check', 'accept-succession', 'help'].includes(key)) args.flags[key] = true;
      else {
        if (i + 1 >= argv.length) throw new Error(`--${key} needs a value`);
        args.flags[key] = argv[++i];
      }
    } else if (a === '-h') {
      args.flags.help = true;
    } else {
      args._.push(a);
    }
  }
  return args;
}

const readJson = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));

function print(obj, json) {
  if (json) {
    process.stdout.write(`${JSON.stringify(obj, (k, v) => (v instanceof Uint8Array ? base64url.encode(v) : typeof v === 'bigint' ? v.toString() : v), 2)}\n`);
  }
}

function human(result) {
  if (result.ok) {
    const lines = [
      `OK  ${result.status}`,
      `  open:    ${result.canonicalUrl}`,
      `  app:     ${result.kApp}  (${result.fingerprint})`,
    ];
    if (result.kPub) lines.push(`  by:      ${result.kPub}`);
    if (result.display) lines.push(`  display: ${result.display}  [${result.badges.join('] [')}]`);
    else lines.push(`  badges:  [${result.badges.join('] [')}]`);
    if (result.share) lines.push(`  share:   ${result.share}`);
    return lines.join('\n');
  }
  const lines = [`${result.failClosed ? 'FAIL-CLOSED' : 'NOT RESOLVED'}  ${result.code}`, `  ${result.message}`];
  if (result.known?.app) lines.push(`  known app:   ${result.known.app}  (default action: ${result.defaultAction ?? 'open-known'})`);
  if (result.offered?.app) lines.push(`  offered app: ${result.offered.app}  (never opened under this name)`);
  if (result.answers) for (const a of result.answers) lines.push(`  ${a.rail.padEnd(6)} says ${a.app}`);
  return lines.join('\n');
}

function exitCodeFor(result) {
  if (result.ok) return 0;
  if (result.code === 'SUCCESSION_OFFERED') return 4;
  if (result.failClosed) return 3;
  return 2;
}

async function main(argv) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`${e.message}\n\n${USAGE}\n`);
    return 1;
  }
  const [command, target] = args._;
  const json = Boolean(args.flags.json);
  if (!command || args.flags.help) {
    process.stdout.write(`${USAGE}\n`);
    return command || args.flags.help ? 0 : 1;
  }

  switch (command) {
    case 'parse': {
      if (!target) break;
      try {
        const parsed = parseKeyWebUrl(target);
        const out = { ...parsed, directives: Object.fromEntries(parsed.directives) };
        if (json) print(out, true);
        else process.stdout.write(`${Object.entries(out).map(([k, v]) => `${k.padEnd(10)} ${typeof v === 'object' ? JSON.stringify(v) : v}`).join('\n')}\n`);
        return 0;
      } catch (e) {
        process.stderr.write(`${e.code ?? 'BAD_URL'}: ${e.message}\n`);
        return 2;
      }
    }
    case 'pin': {
      if (!target) break;
      try {
        const id = parseKwId(target);
        const pin = pinFor(target, args.flags.length ? Number(args.flags.length) : undefined);
        if (json) print({ kwId: target, type: id.type, pin, fingerprint: fingerprint(target) }, true);
        else process.stdout.write(`${pin}\n`);
        return 0;
      } catch (e) {
        process.stderr.write(`${e.message}\n`);
        return 1;
      }
    }
    case 'inspect': {
      if (!target) break;
      try {
        print(inspectRecord(base64url.decode(target)), true);
        return 0;
      } catch (e) {
        process.stderr.write(`${e.message}\n`);
        return 2;
      }
    }
    case 'demo':
      return runDemo({ json, out: process.stdout });
    case 'resolve': {
      if (!target) break;
      if (args.flags.fixtures && args.flags.live) {
        process.stderr.write('choose either --fixtures or --live\n');
        return 1;
      }
      const book = args.flags.book ? readJson(args.flags.book) : undefined;
      let rails = {};
      if (args.flags.fixtures) rails = MockRail.fromFixtures(readJson(args.flags.fixtures));
      else if (args.flags.live) rails = createLiveRails({ book });
      if (book && !rails.local) rails.local = new LocalRail({ book });
      const store = new TrustStore({ file: args.flags.store });
      const resolver = new KeyWebResolver({ rails, store, crossCheck: args.flags['no-cross-check'] ? 'off' : 'sync' });
      const result = await resolver.resolve(target, { acceptSuccession: Boolean(args.flags['accept-succession']) });
      if (json) print(result, true);
      else process.stdout.write(`${human(result)}\n`);
      return exitCodeFor(result);
    }
    default:
      process.stderr.write(`unknown command ${command}\n\n${USAGE}\n`);
      return 1;
  }
  process.stderr.write(`${command}: missing argument\n\n${USAGE}\n`);
  return 1;
}

main(process.argv.slice(2)).then(
  (code) => { process.exitCode = code; },
  (e) => { process.stderr.write(`internal error: ${e.stack ?? e}\n`); process.exitCode = 70; },
);
