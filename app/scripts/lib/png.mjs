// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// An RGBA PNG writer and a strict reader, with nothing but node:zlib.
// The reader is the "scanline check": it proves a file really is 8-bit
// RGBA with one unfiltered scanline per row, and hands back the pixels.

import { deflateSync, inflateSync } from 'node:zlib';

const SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const out = Buffer.alloc(body.length + 8);
  out.writeUInt32BE(data.length, 0);
  body.copy(out, 4);
  out.writeUInt32BE(crc32(body), body.length + 4);
  return out;
}

/** Encodes width x height RGBA pixels (a Buffer of width*height*4 bytes) as a PNG. */
export function encodePng(width, height, rgba) {
  if (rgba.length !== width * height * 4) throw new Error('pixel data does not match the size');
  const stride = width * 4 + 1;
  const raw = Buffer.alloc(height * stride);
  for (let y = 0; y < height; y++) {
    raw[y * stride] = 0;
    rgba.copy(raw, y * stride + 1, y * width * 4, (y + 1) * width * 4);
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;   // bit depth
  header[9] = 6;   // colour type: RGBA
  return Buffer.concat([SIGNATURE, chunk('IHDR', header), chunk('IDAT', deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}

/**
 * The RGBA scanline check. Throws unless the file is a PNG whose chunks all
 * have correct checksums, whose header says 8-bit RGBA without interlacing,
 * and whose image data inflates to exactly height scanlines of
 * 1 + width*4 bytes, each with filter type 0. Returns {width, height, rgba}.
 */
export function decodeRgbaPng(file) {
  if (file.length < 8 || !file.subarray(0, 8).equals(SIGNATURE)) throw new Error('not a PNG');
  let offset = 8;
  let header = null;
  const data = [];
  let ended = false;
  while (offset < file.length) {
    if (ended) throw new Error('bytes after IEND');
    if (offset + 12 > file.length) throw new Error('a chunk is cut short');
    const length = file.readUInt32BE(offset);
    if (offset + 12 + length > file.length) throw new Error('a chunk runs past the end');
    const body = file.subarray(offset + 4, offset + 8 + length);
    if (crc32(body) !== file.readUInt32BE(offset + 8 + length)) throw new Error('a chunk has the wrong checksum');
    const type = body.subarray(0, 4).toString('ascii');
    const payload = body.subarray(4);
    if (type === 'IHDR') {
      if (header || payload.length !== 13) throw new Error('bad IHDR');
      header = { width: payload.readUInt32BE(0), height: payload.readUInt32BE(4), depth: payload[8], colour: payload[9], compression: payload[10], filter: payload[11], interlace: payload[12] };
    } else if (type === 'IDAT') data.push(payload);
    else if (type === 'IEND') ended = true;
    else if (type[0] === type[0].toUpperCase()) throw new Error(`unexpected critical chunk ${type}`);
    offset += 12 + length;
  }
  if (!header || !ended) throw new Error('IHDR or IEND is missing');
  if (header.depth !== 8 || header.colour !== 6) throw new Error(`not 8-bit RGBA (depth ${header.depth}, colour type ${header.colour})`);
  if (header.compression !== 0 || header.filter !== 0 || header.interlace !== 0) throw new Error('unsupported compression, filter method or interlacing');
  const { width, height } = header;
  if (width < 1 || height < 1 || width > 4096 || height > 4096) throw new Error('unreasonable size');
  const stride = width * 4 + 1;
  const raw = inflateSync(Buffer.concat(data));
  if (raw.length !== height * stride) throw new Error(`expected ${height} scanlines of ${stride} bytes, got ${raw.length} bytes`);
  const rgba = Buffer.alloc(width * height * 4);
  for (let y = 0; y < height; y++) {
    if (raw[y * stride] !== 0) throw new Error(`scanline ${y} uses filter type ${raw[y * stride]}`);
    raw.copy(rgba, y * width * 4, y * stride + 1, (y + 1) * stride);
  }
  return { width, height, rgba };
}

/** Counts the fully transparent, partly transparent and opaque pixels. */
export function alphaProfile({ width, height, rgba }) {
  let clear = 0;
  let partial = 0;
  let opaque = 0;
  for (let i = 3; i < rgba.length; i += 4) {
    if (rgba[i] === 0) clear += 1;
    else if (rgba[i] === 255) opaque += 1;
    else partial += 1;
  }
  const alphaAt = (x, y) => rgba[(y * width + x) * 4 + 3];
  return { clear, partial, opaque, corner: alphaAt(0, 0), centre: alphaAt(width >> 1, height >> 1) };
}
