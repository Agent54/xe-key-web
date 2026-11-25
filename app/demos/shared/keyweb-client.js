// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The app side of the runner's message protocol. Every demo app ships its
// own copy of this file inside its signed bundle. It is ordinary app code:
// the runner does not trust it, and an app that never loads it still runs.
//
// An app can do three things with it:
//
//   const runner = connect();
//   const context = await runner.context;                    // {transport, tier, capabilities, lab}
//   const answer = await runner.request('net:sync-relay', 'why I want it');
//   const result = await runner.invoke('net:sync-relay', {op: 'push', data: '…'});
//
// request() asks the person for one capability. invoke() asks the runner
// to carry out one operation under a capability that was granted. The
// app's own sandbox does not change either way.

const RUNNER = `${location.protocol}//localhost${location.port ? `:${location.port}` : ''}`;

export function connect() {
  const framed = window.parent !== window;
  const waiting = new Map();
  const listeners = new Map();
  let nextId = 1;
  let gotContext;
  const context = new Promise((done) => {
    gotContext = done;
  });
  const post = (message) => {
    if (framed) window.parent.postMessage({ keyweb: 1, ...message }, RUNNER);
  };

  if (framed) {
    window.addEventListener('message', (event) => {
      if (event.origin !== RUNNER || event.source !== window.parent) return;
      const message = event.data;
      if (message === null || typeof message !== 'object' || message.keyweb !== 1) return;
      if (message.type === 'context') gotContext({ ...message.context, framed: true });
      else if (message.type === 'cap.result' && waiting.has(message.rid)) {
        const done = waiting.get(message.rid);
        waiting.delete(message.rid);
        done(message);
      } else if (listeners.has(message.type)) listeners.get(message.type)(message);
    });
    post({ type: 'hello' });
    // No runner answering is not an error: carry on with nothing.
    setTimeout(() => gotContext({ framed: true, transport: 'unknown', tier: 0, capabilities: [], lab: {} }), 2000);
  } else {
    gotContext({ framed: false, transport: 'direct', tier: null, capabilities: [], lab: {} });
  }

  const call = (type, body) => new Promise((done) => {
    if (!framed) {
      done({ ok: false, error: 'NO_RUNNER' });
      return;
    }
    const rid = nextId++;
    waiting.set(rid, done);
    post({ type, rid, ...body });
  });

  return {
    framed,
    context,
    /** Asks the person for one capability. Resolves with {ok, mode, expires} or {ok: false, error}. */
    request: (capability, reason) => call('cap.request', { cap: capability, reason }),
    /** Asks the runner to perform one operation. Resolves with {ok, result} or {ok: false, error}. */
    invoke: (capability, args) => call('cap.invoke', { cap: capability, args }),
    /** Tells the runner something, with no answer expected. */
    tell: (type, data) => post({ type, data }),
    /** Hears one kind of message the runner sends unasked. */
    listen: (type, handler) => listeners.set(type, handler),
  };
}
