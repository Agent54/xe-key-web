// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The policies, as data. The dev server, the service worker that serves a
// key origin, the packager and the tests all read them from here, so what
// is tested is what is enforced.

/**
 * Tier 0, the zero-exfiltration default. It is put on every response a key
 * origin serves, whatever the bundle's own headers say: the sandbox is the
 * browser's promise to the user, not the app's.
 *
 *   connect-src 'none'   no fetch, XHR, beacon, WebSocket or EventSource
 *   img-src 'self'       the app's own images render, a tracking pixel does not
 *   form-action 'none'   no form can carry data anywhere
 *   default-src 'none'   and nothing else is fetched from anywhere either
 *
 * What a page's policy cannot do, measured in Chrome 158: stop WebRTC from
 * sending STUN and TURN packets, or stop <link rel="preconnect"> from
 * opening a bare connection. The CSP "webrtc" directive that would cover
 * the first is not implemented there. Those two need the browser itself;
 * LeakyTracker probes them and the tracker counts what arrives.
 */
export function sandboxCsp({ runnerOrigin, reportUri = null }) {
  const policy = [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self'",
    "font-src 'self'",
    "media-src 'self'",
    "connect-src 'none'",
    "form-action 'none'",
    "frame-src 'none'",
    "worker-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    `frame-ancestors ${runnerOrigin}`,
    "require-trusted-types-for 'script'",
    "trusted-types 'none'",
  ];
  if (reportUri) policy.push(`report-uri ${reportUri}`);
  return policy.join('; ');
}

/** What the runner allows the frame it puts a key origin in. No popups, no top navigation, no downloads. */
export const FRAME_SANDBOX = Object.freeze(['allow-scripts', 'allow-same-origin', 'allow-forms']);

const DENIED_FEATURES = [
  'accelerometer', 'autoplay', 'bluetooth', 'camera', 'clipboard-read', 'clipboard-write', 'display-capture', 'geolocation',
  'gyroscope', 'hid', 'magnetometer', 'microphone', 'midi', 'payment', 'publickey-credentials-get', 'screen-wake-lock',
  'serial', 'usb', 'xr-spatial-tracking',
];

export const SANDBOX_PERMISSIONS = DENIED_FEATURES.map((feature) => `${feature}=()`).join(', ');

/** Headers on every response a key origin serves from its verified bundle. */
export function sandboxHeaders({ id, runnerOrigin, reportUri = null, contentType }) {
  return {
    'Content-Type': contentType,
    'Content-Security-Policy': sandboxCsp({ runnerOrigin, reportUri }),
    'Permissions-Policy': SANDBOX_PERMISSIONS,
    'Cross-Origin-Resource-Policy': 'same-origin',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
    'X-Key-Web-Origin': `key-web://${id}/`,
  };
}

/**
 * Decides one request to a key origin. `state` is what the service worker
 * holds after verifying the installed bundle: {id, exchanges} or null.
 * Returns {status, headers, body}; the worker turns that into a Response.
 */
export function responseFor(state, { method, pathname, destination, navigation = false, armed = false, runnerOrigin, reportUri = null }) {
  const plain = (status, text) => ({
    status,
    headers: sandboxHeaders({ id: state ? state.id : 'unverified', runnerOrigin, reportUri, contentType: 'text/plain; charset=utf-8' }),
    body: text,
  });
  if (method !== 'GET' && method !== 'HEAD') return plain(405, 'a key origin only answers GET');
  if (!state || !(state.exchanges instanceof Map)) return plain(409, 'no verified bundle is installed for this key origin');
  // A key origin is only ever shown inside the runner's sandboxed frame.
  if (destination === 'document') return plain(403, 'a key origin opens inside KeyWeb Runner, not as a page of its own');
  // A document is served once per boot, and only after the runner asked the
  // loader for it. So no app can navigate a frame into this origin to hand
  // it data in a URL, and an app that navigates itself gets nothing back.
  if (navigation && !armed) return plain(403, 'this key origin was not opened by KeyWeb Runner');
  const exchange = state.exchanges.get(pathname);
  if (!exchange) return plain(404, 'not in the signed bundle');
  return {
    status: 200,
    headers: sandboxHeaders({ id: state.id, runnerOrigin, reportUri, contentType: exchange.headers['content-type'] }),
    body: exchange.payload,
  };
}

/**
 * The runner page. Script and style come only from its own files, Trusted
 * Types are required and no policy may be created, it may fetch from itself
 * and from the mirror port, and the only thing it may frame is a key origin
 * on its own port. That last line is also what stops a sandboxed app from
 * navigating its own frame out to a server.
 */
export function runnerCsp({ appPort, mirrorPort }) {
  return [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self'",
    `connect-src 'self' http://localhost:${mirrorPort} http://*.localhost:${mirrorPort}`,
    `frame-src http://*.localhost:${appPort}`,
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "require-trusted-types-for 'script'",
    "trusted-types 'none'",
  ].join('; ');
}

/**
 * The key-origin loader: the one page that installs a verified bundle. It
 * may only talk to its own origin, which it does once, to prove the service
 * worker answers. Registering a service worker is a Trusted Types sink, so
 * this page alone is allowed one policy, by name, and that policy can only
 * ever produce the worker's own fixed URL.
 */
export const LOADER_POLICY_NAME = 'keyweb-loader';

export function loaderCsp({ runnerOrigin }) {
  return [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "connect-src 'self'",
    "worker-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    `frame-ancestors ${runnerOrigin}`,
    "require-trusted-types-for 'script'",
    `trusted-types ${LOADER_POLICY_NAME}`,
  ].join('; ');
}

/** The service worker's own policy: it may import its modules and nothing else. It cannot reach the network. */
export const WORKER_CSP = ["default-src 'none'", "script-src 'self'", "connect-src 'none'"].join('; ');

/**
 * Stored on every resource inside the runner's own signed bundle. An
 * installed Isolated Web App gets Chromium's built-in policy on top of
 * this one, which allows only secure origins.
 */
export const BUNDLE_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "connect-src 'self' https: wss:",
  "frame-src 'self' https:",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'self'",
  "require-trusted-types-for 'script'",
  "trusted-types 'none'",
].join('; ');

/** Where the runner lives, as seen from a key origin on the same port. */
export function runnerOriginFrom(location) {
  return `${location.protocol}//localhost${location.port ? `:${location.port}` : ''}`;
}

/** http://<id>.localhost:<port>: the real browser origin that stands in for key-web://<id>/. */
export function keyOriginUrl(id, { protocol = 'http:', port }) {
  return `${protocol}//${id}.localhost${port ? `:${port}` : ''}`;
}
