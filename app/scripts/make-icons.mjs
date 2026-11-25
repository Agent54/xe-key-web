#!/usr/bin/env node
// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// Draws every raster image in the project with nothing but node:zlib: the
// runner's icon, and an icon and a cover for each demo app. The PNGs are
// committed, so a build needs no image tools.
//
//   node scripts/make-icons.mjs            draw and write them all
//   node scripts/make-icons.mjs --check    change nothing; fail unless every committed file
//                                          passes the RGBA scanline check and holds exactly
//                                          the pixels this script draws
//
// The scanline check (scripts/lib/png.mjs) proves each file is 8-bit RGBA
// with one unfiltered scanline per row and correct checksums. Pixels are
// compared, not file bytes, because zlib's output may differ between Node
// versions while the image may not.
//
// The covers carry film grain on purpose. It makes each demo bundle several
// 16 KB chunks long, so the swarm transport has something to show.

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { alphaProfile, decodeRgbaPng, encodePng } from './lib/png.mjs';
import { DEMOS_DIR, REPO_ROOT, RUNNER_DIR } from './lib/site.mjs';

const SAMPLES = 4;
const hex = (value) => [parseInt(value.slice(1, 3), 16), parseInt(value.slice(3, 5), 16), parseInt(value.slice(5, 7), 16)];
const mix = (a, b, t) => a.map((channel, i) => channel + (b[i] - channel) * t);

// ---------------------------------------------------------------- shapes, on a 256-unit grid

function roundRect(x, y, left, top, width, height, radius) {
  if (x < left || x > left + width || y < top || y > top + height) return false;
  const cx = Math.min(Math.max(x, left + radius), left + width - radius);
  const cy = Math.min(Math.max(y, top + radius), top + height - radius);
  return (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2;
}

const disc = (x, y, cx, cy, radius) => (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2;
const ring = (x, y, cx, cy, outer, inner) => disc(x, y, cx, cy, outer) && !disc(x, y, cx, cy, inner);

function segment(x, y, [ax, ay], [bx, by], half) {
  const dx = bx - ax;
  const dy = by - ay;
  const t = Math.min(1, Math.max(0, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)));
  return (x - ax - t * dx) ** 2 + (y - ay - t * dy) ** 2 <= half ** 2;
}

const AMBER = hex('#f2b23a');
const TEAL = hex('#35c2a1');
const PAPER = hex('#f4efe2');
const RED = hex('#e5484d');

/** Each returns the colour at a point of the 256 grid, or null where the image is transparent. */
const DRAW = {
  // A key whose bow is a node in a small web.
  runner(x, y) {
    if (!roundRect(x, y, 0, 0, 256, 256, 56)) return null;
    let colour = hex('#14161c');
    for (const [from, to] of [[[92, 132], [176, 62]], [[176, 62], [212, 96]], [[92, 132], [60, 62]]]) if (segment(x, y, from, to, 3)) colour = hex('#3a4252');
    if (disc(x, y, 176, 62, 13)) colour = TEAL;
    if (disc(x, y, 212, 96, 9)) colour = TEAL;
    if (disc(x, y, 60, 62, 9)) colour = TEAL;
    if (ring(x, y, 92, 132, 46, 21)) colour = AMBER;
    if (roundRect(x, y, 130, 120, 96, 24, 6)) colour = AMBER;
    if (roundRect(x, y, 182, 138, 16, 30, 4) || roundRect(x, y, 208, 138, 16, 22, 4)) colour = AMBER;
    return colour;
  },
  // A sheet of paper with ruled lines and one pencil stroke.
  localpad(x, y) {
    if (!roundRect(x, y, 0, 0, 256, 256, 56)) return null;
    let colour = hex('#1d2433');
    if (roundRect(x, y, 56, 40, 144, 176, 14)) colour = PAPER;
    for (const line of [84, 112, 140, 168]) if (segment(x, y, [80, line], [176, line], 4)) colour = hex('#a8afbe');
    if (segment(x, y, [146, 196], [208, 118], 9)) colour = AMBER;
    if (disc(x, y, 146, 196, 5)) colour = hex('#1d2433');
    return colour;
  },
  // An eye behind a "no entry" sign.
  leakytracker(x, y) {
    if (!roundRect(x, y, 0, 0, 256, 256, 56)) return null;
    let colour = hex('#261a1f');
    if (disc(x, y, 128, 128, 34)) colour = PAPER;
    if (disc(x, y, 128, 128, 15)) colour = hex('#261a1f');
    if (ring(x, y, 128, 128, 86, 68)) colour = RED;
    if (segment(x, y, [72, 184], [184, 72], 9)) colour = RED;
    return colour;
  },
  // A calculator: a display, six keys, one of them lit.
  'peersync-calc': (x, y) => {
    if (!roundRect(x, y, 0, 0, 256, 256, 56)) return null;
    let colour = hex('#132429');
    if (roundRect(x, y, 52, 46, 152, 44, 10)) colour = hex('#9fe3d3');
    for (const top of [106, 162]) {
      for (const left of [52, 108, 164]) {
        if (roundRect(x, y, left, top, 40, 40, 9)) colour = top === 162 && left === 164 ? AMBER : hex('#dfe9ea');
      }
    }
    return colour;
  },
};

const COVERS = {
  localpad: { from: hex('#1d2433'), to: hex('#3b4a6b'), accent: AMBER },
  leakytracker: { from: hex('#2a1418'), to: hex('#6b2630'), accent: RED },
  'peersync-calc': { from: hex('#0f2226'), to: hex('#1f5a57'), accent: TEAL },
};

/** A small deterministic generator, so the grain is the same on every machine. */
function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function renderIcon(name, size) {
  const draw = DRAW[name];
  const scale = 256 / size;
  const rgba = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let r = 0;
      let g = 0;
      let b = 0;
      let hits = 0;
      for (let sy = 0; sy < SAMPLES; sy++) {
        for (let sx = 0; sx < SAMPLES; sx++) {
          const colour = draw((x + (sx + 0.5) / SAMPLES) * scale, (y + (sy + 0.5) / SAMPLES) * scale);
          if (!colour) continue;
          r += colour[0];
          g += colour[1];
          b += colour[2];
          hits += 1;
        }
      }
      const at = (y * size + x) * 4;
      rgba[at] = hits ? Math.round(r / hits) : 0;
      rgba[at + 1] = hits ? Math.round(g / hits) : 0;
      rgba[at + 2] = hits ? Math.round(b / hits) : 0;
      rgba[at + 3] = Math.round((hits / (SAMPLES * SAMPLES)) * 255);
    }
  }
  return { width: size, height: size, rgba };
}

function renderCover(name, width, height, seed) {
  const { from, to, accent } = COVERS[name];
  const random = mulberry32(seed);
  const rgba = Buffer.alloc(width * height * 4);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const inside = roundRect(x + 0.5, y + 0.5, 0, 0, width, height, 14);
      const at = (y * width + x) * 4;
      if (!inside) continue;
      let colour = mix(from, to, x / (width - 1));
      // Diagonal bands, and a row of beads along the bottom.
      if (((x + y * 2) % 56) < 3) colour = mix(colour, accent, 0.35);
      if (disc(x % 32, y, 16, height - 22, 4)) colour = mix(colour, accent, 0.8);
      for (let c = 0; c < 3; c++) rgba[at + c] = Math.max(0, Math.min(255, Math.round(colour[c] + (random() - 0.5) * 12)));
      rgba[at + 3] = 255;
    }
  }
  return { width, height, rgba };
}

/** Every image this project commits: [absolute path, how to draw it]. */
export const IMAGES = Object.freeze([
  [join(RUNNER_DIR, 'icon-256.png'), () => renderIcon('runner', 256)],
  ...Object.keys(COVERS).flatMap((name, index) => [
    [join(DEMOS_DIR, name, 'icon-192.png'), () => renderIcon(name, 192)],
    [join(DEMOS_DIR, name, 'cover.png'), () => renderCover(name, 400, 150, 0x6b657977 + index)],
  ]),
]);

/**
 * Checks every committed image. Returns [{path, ok, problem, width, height, alpha}].
 * An icon must have transparent corners and an opaque centre.
 */
export function checkImages(images = IMAGES) {
  return images.map(([file, draw]) => {
    const path = relative(REPO_ROOT, file);
    if (!existsSync(file)) return { path, ok: false, problem: 'missing (run node scripts/make-icons.mjs)' };
    let decoded;
    try {
      decoded = decodeRgbaPng(readFileSync(file));
    } catch (error) {
      return { path, ok: false, problem: `scanline check failed: ${error.message}` };
    }
    const expected = draw();
    const alpha = alphaProfile(decoded);
    const base = { path, width: decoded.width, height: decoded.height, alpha };
    if (decoded.width !== expected.width || decoded.height !== expected.height) return { ...base, ok: false, problem: 'wrong size' };
    if (!decoded.rgba.equals(expected.rgba)) return { ...base, ok: false, problem: 'pixels differ from what this script draws (run it again)' };
    if (alpha.corner !== 0 || alpha.centre !== 255) return { ...base, ok: false, problem: 'corners must be transparent and the centre opaque' };
    return { ...base, ok: true, problem: null };
  });
}

function main(argv) {
  if (!argv.includes('--check')) {
    for (const [file, draw] of IMAGES) {
      const { width, height, rgba } = draw();
      const png = encodePng(width, height, rgba);
      writeFileSync(file, png);
      console.log(`wrote     ${relative(REPO_ROOT, file)}  ${width}x${height}, ${png.length} bytes`);
    }
  }
  const results = checkImages();
  for (const result of results) {
    if (result.ok) console.log(`rgba ok   ${result.path}  ${result.width}x${result.height}, ${result.alpha.clear} clear / ${result.alpha.partial} soft / ${result.alpha.opaque} opaque pixels`);
    else console.error(`rgba FAIL ${result.path}  ${result.problem}`);
  }
  const failed = results.filter((result) => !result.ok).length;
  console.log(`icons: ${results.length} images, ${failed} problem${failed === 1 ? '' : 's'}`);
  process.exitCode = failed === 0 ? 0 : 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main(process.argv.slice(2));
