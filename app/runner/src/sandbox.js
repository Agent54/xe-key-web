// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The frame a key origin runs in, and the conversation with its loader.
//
// A key origin is a real browser origin, http://<id>.localhost:<port>, so
// the browser itself keeps its storage apart from every other key's. The
// runner frames it with a sandbox that allows scripts and its own origin
// and nothing else: no popups, no top-level navigation, no downloads. The
// runner's own policy (frame-src) stops the frame from being navigated to
// any server that is not a key origin.
//
// Boot is three steps, and the frame may load exactly twice:
//   1. the loader page                    -> it says "loader.ready"
//   2. the verified bytes are handed over -> it says "install.ok"
//   3. the app's entry point              -> the service worker serves it from the bundle
// A third load means something navigated the frame. The app is torn down.

import { FRAME_SANDBOX, keyOriginUrl } from './engine/policy.js';

const LOADER_PATH = '/__keyweb/loader.html';

export class SandboxError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'SandboxError';
    this.code = code;
  }
}

function makeFrame(title, hidden) {
  const frame = document.createElement('iframe');
  frame.setAttribute('sandbox', FRAME_SANDBOX.join(' '));
  frame.setAttribute('referrerpolicy', 'no-referrer');
  frame.setAttribute('allow', '');
  frame.setAttribute('title', title);
  frame.className = hidden ? 'frame-hidden' : 'app-frame';
  return frame;
}

/**
 * Opens a channel to one frame at one origin. `handler` gets every
 * well-formed message that really came from that frame's window while it
 * was at that origin. Returns {post, request, close}.
 */
function channel(frame, origin, handler) {
  const waiting = new Map();
  let nextId = 1;
  const listener = (event) => {
    if (event.source !== frame.contentWindow || event.origin !== origin) return;
    const message = event.data;
    if (message === null || typeof message !== 'object' || message.keyweb !== 1 || typeof message.type !== 'string') return;
    if (message.rid !== undefined && waiting.has(message.rid)) {
      const { done, fail, timer } = waiting.get(message.rid);
      waiting.delete(message.rid);
      clearTimeout(timer);
      if (message.type === 'failed') fail(new SandboxError(String(message.code || 'LOADER_FAILED'), String(message.detail || 'the loader refused')));
      else done(message);
      return;
    }
    handler(message);
  };
  window.addEventListener('message', listener);
  const post = (message, transfer = []) => frame.contentWindow.postMessage({ keyweb: 1, ...message }, origin, transfer);
  return {
    post,
    /** Sends a request to the loader and resolves with its reply, or rejects with its refusal. */
    request(message, { timeout = 20000, transfer = [] } = {}) {
      return new Promise((done, fail) => {
        const rid = nextId++;
        const timer = setTimeout(() => {
          waiting.delete(rid);
          fail(new SandboxError('LOADER_TIMEOUT', 'the key-origin loader did not answer'));
        }, timeout);
        waiting.set(rid, { done, fail, timer });
        post({ ...message, rid }, transfer);
      });
    },
    close() {
      window.removeEventListener('message', listener);
      for (const { fail, timer } of waiting.values()) {
        clearTimeout(timer);
        fail(new SandboxError('CLOSED', 'the frame was closed'));
      }
      waiting.clear();
    },
  };
}

/** Loads a key origin's loader in `frame` and resolves once it reports for duty. */
function openLoader(frame, origin, onMessage) {
  return new Promise((done, fail) => {
    let link = null;
    const refuse = (error) => {
      if (link) link.close();
      fail(error);
    };
    const timer = setTimeout(() => refuse(new SandboxError('LOADER_UNREACHABLE', 'the key-origin loader did not start (is the runner being served by scripts/serve.mjs?)')), 10000);
    link = channel(frame, origin, (message) => {
      if (message.type === 'loader.ready') {
        clearTimeout(timer);
        if (message.storage !== true) refuse(new SandboxError('STORAGE_BLOCKED', 'this browser blocks storage and service workers for embedded origins, so a key origin cannot be set up'));
        else done(link);
        return;
      }
      onMessage(message);
    });
    frame.src = `${origin}${LOADER_PATH}`;
  });
}

/**
 * Runs one loader command (storage.export, storage.import, storage.clear)
 * against a key origin in a hidden frame, and resolves with the reply.
 */
export async function loaderCommand({ id, port, protocol, command }) {
  const origin = keyOriginUrl(id, { protocol, port });
  const frame = makeFrame('Key origin maintenance', true);
  document.body.append(frame);
  let link = null;
  try {
    link = await openLoader(frame, origin, () => {});
    return await link.request(command);
  } finally {
    if (link) link.close();
    frame.remove();
  }
}

export class Sandbox {
  /**
   * container  where the frame goes
   * id         the verified key ID
   * onMessage  called with every message the running app sends
   * onEvent    called with {type: 'phase', phase} and {type: 'navigation'}
   */
  constructor({ container, id, port, protocol, title, onMessage, onEvent = () => {} }) {
    this.id = id;
    this.origin = keyOriginUrl(id, { protocol, port });
    this.container = container;
    this.onMessage = onMessage;
    this.onEvent = onEvent;
    this.phase = 'new';
    this.frame = makeFrame(title, false);
    this.link = null;
    this.loads = 0;
    this.appLoaded = null;
    this.frame.addEventListener('load', () => this.onLoad());
  }

  setPhase(phase) {
    this.phase = phase;
    this.onEvent({ type: 'phase', phase });
  }

  onLoad() {
    this.loads += 1;
    if (this.phase === 'opening' && this.appLoaded) {
      this.appLoaded();
      this.appLoaded = null;
    } else if (this.phase === 'running') {
      // The app navigated its own frame. Whatever it went to, it is not the
      // document that was verified, so it does not get to stay.
      this.onEvent({ type: 'navigation' });
      this.destroy();
    }
  }

  /** Hands verified bytes to the key origin and opens the app. Rejects with a SandboxError. */
  async boot(bytes) {
    this.container.append(this.frame);
    this.setPhase('loader');
    // An app's scripts run before its frame's load event, so its first
    // messages arrive while the frame is still "opening".
    const live = () => this.phase === 'opening' || this.phase === 'running';
    const link = await openLoader(this.frame, this.origin, (message) => {
      if (live()) this.onMessage(message);
    });
    if (this.phase !== 'loader') {
      link.close();
      throw new SandboxError('CLOSED', 'the frame was closed');
    }
    this.link = link;
    this.setPhase('installing');
    const copy = bytes.slice().buffer;
    const reply = await this.link.request({ type: 'install', swbn: copy }, { transfer: [copy] });
    if (this.phase !== 'installing') throw new SandboxError('CLOSED', 'the frame was closed');
    this.setPhase('opening');
    await new Promise((done, fail) => {
      const timer = setTimeout(() => fail(new SandboxError('APP_TIMEOUT', 'the app did not load')), 10000);
      this.appLoaded = () => {
        clearTimeout(timer);
        done();
      };
      this.abortOpen = () => {
        clearTimeout(timer);
        fail(new SandboxError('CLOSED', 'the frame was closed'));
      };
      this.frame.src = `${this.origin}/`;
    });
    this.abortOpen = null;
    this.setPhase('running');
    return reply;
  }

  post(message) {
    if ((this.phase === 'opening' || this.phase === 'running') && this.link) this.link.post(message);
  }

  destroy() {
    if (this.phase === 'closed') return;
    this.phase = 'closed';
    if (this.abortOpen) this.abortOpen();
    this.abortOpen = null;
    if (this.link) this.link.close();
    this.link = null;
    this.frame.remove();
    this.onEvent({ type: 'phase', phase: 'closed' });
  }
}
