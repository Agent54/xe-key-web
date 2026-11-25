// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The committed images and the RGBA scanline check.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, test } from 'node:test';
import { deflateSync } from 'node:zlib';
import { alphaProfile, decodeRgbaPng, encodePng } from '../scripts/lib/png.mjs';
import { REPO_ROOT } from '../scripts/lib/site.mjs';
import { IMAGES, checkImages } from '../scripts/make-icons.mjs';

describe('the committed images', () => {
  const results = checkImages();

  test('all pass the RGBA scanline check and hold exactly the pixels the script draws', () => {
    assert.equal(results.length, 7);
    for (const result of results) assert.equal(result.problem, null, result.path);
    assert.deepEqual(results.map((result) => result.path).sort(), [
      'demos/leakytracker/cover.png', 'demos/leakytracker/icon-192.png', 'demos/localpad/cover.png', 'demos/localpad/icon-192.png',
      'demos/peersync-calc/cover.png', 'demos/peersync-calc/icon-192.png', 'runner/icon-256.png',
    ]);
  });

  test('icons are square with transparent rounded corners, soft edges and an opaque middle', () => {
    for (const result of results.filter((entry) => entry.path.includes('icon-'))) {
      assert.equal(result.width, result.height, result.path);
      assert.equal(result.alpha.corner, 0, result.path);
      assert.equal(result.alpha.centre, 255, result.path);
      assert.ok(result.alpha.clear > 0 && result.alpha.partial > 0 && result.alpha.opaque > result.alpha.clear, result.path);
    }
    assert.equal(results.find((entry) => entry.path === 'runner/icon-256.png').width, 256);
  });

  test("the runner's manifest names an icon that exists at the size it says", () => {
    const manifest = JSON.parse(readFileSync(join(REPO_ROOT, 'runner', '.well-known', 'manifest.webmanifest'), 'utf8'));
    const [icon] = manifest.icons;
    const decoded = decodeRgbaPng(readFileSync(join(REPO_ROOT, 'runner', icon.src)));
    assert.equal(`${decoded.width}x${decoded.height}`, icon.sizes);
    assert.equal(icon.type, 'image/png');
  });

  test('a changed pixel, a missing file and a wrong size are all caught', () => {
    const [file, draw] = IMAGES[0];
    const changed = () => {
      const image = draw();
      image.rgba[image.rgba.length / 2] ^= 1;
      return image;
    };
    assert.match(checkImages([[file, changed]])[0].problem, /pixels differ/);
    assert.match(checkImages([[`${file}.missing`, draw]])[0].problem, /missing/);
    assert.match(checkImages([[file, () => ({ width: 8, height: 8, rgba: Buffer.alloc(256) })]])[0].problem, /wrong size/);
    assert.match(checkImages([[join(REPO_ROOT, 'LICENSE'), draw]])[0].problem, /scanline check failed: not a PNG/);
  });
});

describe('the PNG writer and the scanline check', () => {
  const pixels = Buffer.from([255, 0, 0, 255, 0, 255, 0, 128, 0, 0, 255, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 255, 254]);

  test('round-trip every pixel', () => {
    const png = encodePng(3, 2, pixels);
    const decoded = decodeRgbaPng(png);
    assert.deepEqual({ width: decoded.width, height: decoded.height }, { width: 3, height: 2 });
    assert.deepEqual([...decoded.rgba], [...pixels]);
    // Alpha values, in order: 255, 128, 0, 6, 2, 254.
    assert.deepEqual(alphaProfile(decoded), { clear: 1, partial: 4, opaque: 1, corner: 255, centre: 2 });
    assert.throws(() => encodePng(3, 3, pixels), /does not match/);
  });

  /** Rebuilds a PNG with a different header and image data, with correct checksums. */
  function craft({ width = 3, height = 2, depth = 8, colour = 6, interlace = 0, raw }) {
    const table = Array.from({ length: 256 }, (_, n) => {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      return c >>> 0;
    });
    const chunk = (type, data) => {
      const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
      let crc = 0xffffffff;
      for (const byte of body) crc = table[(crc ^ byte) & 0xff] ^ (crc >>> 8);
      const out = Buffer.alloc(body.length + 8);
      out.writeUInt32BE(data.length, 0);
      body.copy(out, 4);
      out.writeUInt32BE((crc ^ 0xffffffff) >>> 0, body.length + 4);
      return out;
    };
    const header = Buffer.alloc(13);
    header.writeUInt32BE(width, 0);
    header.writeUInt32BE(height, 4);
    header[8] = depth;
    header[9] = colour;
    header[12] = interlace;
    return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', header), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
  }
  const scanlines = (filter) => Buffer.concat([Buffer.from([0]), pixels.subarray(0, 12), Buffer.from([filter]), pixels.subarray(12)]);

  test('accepts a well-formed file built by hand', () => {
    assert.deepEqual([...decodeRgbaPng(craft({ raw: scanlines(0) })).rgba], [...pixels]);
  });

  test('rejects anything that is not 8-bit RGBA with unfiltered scanlines', () => {
    assert.throws(() => decodeRgbaPng(craft({ colour: 2, raw: scanlines(0) })), /not 8-bit RGBA/);
    assert.throws(() => decodeRgbaPng(craft({ depth: 16, raw: scanlines(0) })), /not 8-bit RGBA/);
    assert.throws(() => decodeRgbaPng(craft({ interlace: 1, raw: scanlines(0) })), /interlacing/);
    assert.throws(() => decodeRgbaPng(craft({ raw: scanlines(1) })), /scanline 1 uses filter type 1/);
    assert.throws(() => decodeRgbaPng(craft({ raw: scanlines(0).subarray(0, 20) })), /expected 2 scanlines of 13 bytes/);
    assert.throws(() => decodeRgbaPng(craft({ height: 3, raw: scanlines(0) })), /expected 3 scanlines/);
    assert.throws(() => decodeRgbaPng(craft({ width: 0, raw: scanlines(0) })), /unreasonable size/);
  });

  test('rejects damaged files', () => {
    const png = encodePng(3, 2, pixels);
    const flipped = Buffer.from(png);
    flipped[20] ^= 1;
    assert.throws(() => decodeRgbaPng(flipped), /wrong checksum/);
    assert.throws(() => decodeRgbaPng(png.subarray(0, png.length - 4)), /cut short|runs past/);
    assert.throws(() => decodeRgbaPng(Buffer.concat([png, Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])])), /after IEND/);
    assert.throws(() => decodeRgbaPng(Buffer.from('GIF89a')), /not a PNG/);
    assert.throws(() => decodeRgbaPng(png.subarray(0, 8)), /IHDR or IEND is missing/);
  });
});
