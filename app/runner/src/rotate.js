// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// What happens after a rotation certificate has been verified, and where
// the commitment it is checked against comes from. Shared by the rotation
// simulator and by name resolution, so a rotation means the same thing
// whichever way it arrives.

import { readDescriptor, verifySwbn } from './engine/swbn.js';
import { loaderCommand } from './sandbox.js';

/**
 * The next-key commitment of a key, read from a bundle that key signed.
 * Only a verified bundle is believed: not a catalog, and not a resolver.
 * `fetchBundle(id)` is asked when the local cache has nothing. Resolves
 * with the digest, or null if there is no bundle or no commitment.
 */
export async function commitmentFor(id, { cache, fetchBundle }) {
  const cached = await cache.latest(id);
  const bytes = cached ? cached.bytes : await fetchBundle(id);
  if (!bytes) return null;
  return readDescriptor(await verifySwbn(bytes, { expectedId: id })).nextKeyDigest;
}

/**
 * Makes an accepted rotation take effect: remembers it, carries the old
 * origin's local data to the new origin, and lets the petname follow.
 * `report` is a successful verifyRotation() result. `say(kind, text)` is
 * told what was done. Resolves with {migrated, kept, failed}.
 */
export async function adoptRotation({ fromId, report, certificate, committedDigest, rotations, petnames, say = () => {} }) {
  rotations.accept(fromId, { to: report.to, sequence: report.sequence, certificate, committedDigest });
  const outcome = { migrated: 0, kept: 0, failed: null };
  // The two keys are two browser origins, so the data has to be carried
  // across: read by the old origin's loader, written by the new one's.
  try {
    const options = { port: location.port, protocol: location.protocol };
    const exported = await loaderCommand({ ...options, id: fromId, command: { type: 'storage.export' } });
    const imported = await loaderCommand({ ...options, id: report.to, command: { type: 'storage.import', entries: exported.entries, overwrite: false } });
    outcome.migrated = imported.written;
    outcome.kept = imported.kept;
    say('ok', `Local-first data migrated: ${imported.written} item${imported.written === 1 ? '' : 's'} (${exported.bytes} characters) copied to the new key's origin${imported.kept ? `, ${imported.kept} already there and left alone` : ''}.`);
  } catch (error) {
    outcome.failed = error.code || error.message;
    say('bad', `The rotation stands, but the data could not be migrated (${outcome.failed}).`);
  }
  if (petnames.follow(fromId, report.to, `followed key rotation ${report.sequence}`)) {
    say('ok', `Petname “${petnames.nameFor(report.to)}” followed the origin to its new key.`);
  }
  return outcome;
}
