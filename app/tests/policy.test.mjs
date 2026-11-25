// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The policies as data, and the one function that decides every response a
// key origin gives.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  BUNDLE_CSP, FRAME_SANDBOX, LOADER_POLICY_NAME, SANDBOX_PERMISSIONS, WORKER_CSP, keyOriginUrl, loaderCsp, responseFor, runnerCsp,
  runnerOriginFrom, sandboxCsp, sandboxHeaders,
} from '../runner/src/engine/policy.js';
import { verifySwbn } from '../runner/src/engine/swbn.js';
import { tinyBundle } from './helpers.mjs';

const RUNNER = 'http://localhost:5760';
const directives = (policy) => new Map(policy.split('; ').map((directive) => {
  const [name, ...values] = directive.split(' ');
  return [name, values.join(' ')];
}));

describe('Tier 0, the zero-exfiltration sandbox policy', () => {
  const policy = directives(sandboxCsp({ runnerOrigin: RUNNER, reportUri: `${RUNNER}/api/csp-report?o=x` }));

  test('closes every way out', () => {
    assert.equal(policy.get('default-src'), "'none'");
    assert.equal(policy.get('connect-src'), "'none'");
    assert.equal(policy.get('img-src'), "'self'");
    assert.equal(policy.get('form-action'), "'none'");
    assert.equal(policy.get('frame-src'), "'none'");
    assert.equal(policy.get('worker-src'), "'none'");
    assert.equal(policy.get('object-src'), "'none'");
    assert.equal(policy.get('base-uri'), "'none'");
  });

  test('lets the app be an app: its own script, style, images, fonts and media', () => {
    for (const name of ['script-src', 'style-src', 'img-src', 'font-src', 'media-src']) assert.equal(policy.get(name), "'self'");
  });

  test('has no wildcard, no scheme source, no inline or eval allowance', () => {
    const text = sandboxCsp({ runnerOrigin: RUNNER });
    for (const loose of ['*', 'https:', 'http:', 'data:', 'blob:', 'unsafe-inline', 'unsafe-eval', 'wasm-unsafe-eval']) {
      assert.ok(!text.replace(RUNNER, '').includes(loose), `the sandbox policy contains ${loose}`);
    }
  });

  test('contains only directives the browser understands', () => {
    // The CSP "webrtc" directive would be the right tool for one known gap,
    // but Chrome does not implement it and logs an error for every
    // document that carries it. It stays out until it means something.
    assert.deepEqual([...policy.keys()], [
      'default-src', 'script-src', 'style-src', 'img-src', 'font-src', 'media-src', 'connect-src', 'form-action', 'frame-src', 'worker-src',
      'object-src', 'base-uri', 'frame-ancestors', 'require-trusted-types-for', 'trusted-types', 'report-uri',
    ]);
  });

  test('requires Trusted Types and allows no policy', () => {
    assert.equal(policy.get('require-trusted-types-for'), "'script'");
    assert.equal(policy.get('trusted-types'), "'none'");
  });

  test('may only be framed by the runner, and reports to it', () => {
    assert.equal(policy.get('frame-ancestors'), RUNNER);
    assert.equal(policy.get('report-uri'), `${RUNNER}/api/csp-report?o=x`);
    assert.ok(!sandboxCsp({ runnerOrigin: RUNNER }).includes('report-uri'));
  });

  test('the frame gets scripts, its own origin and forms, and nothing that reaches outside it', () => {
    assert.deepEqual([...FRAME_SANDBOX].sort(), ['allow-forms', 'allow-same-origin', 'allow-scripts']);
    for (const flag of ['allow-popups', 'allow-top-navigation', 'allow-top-navigation-by-user-activation', 'allow-downloads', 'allow-modals', 'allow-popups-to-escape-sandbox']) {
      assert.ok(!FRAME_SANDBOX.includes(flag));
    }
    for (const feature of ['camera', 'microphone', 'geolocation', 'usb', 'serial', 'clipboard-read']) assert.ok(SANDBOX_PERMISSIONS.includes(`${feature}=()`));
  });
});

describe('what a key origin serves', () => {
  const context = { runnerOrigin: RUNNER, reportUri: `${RUNNER}/api/csp-report?o=x`, destination: 'script' };
  const stateOf = async (bundle) => {
    const report = await verifySwbn(bundle.swbn);
    return { id: report.id, exchanges: report.exchanges };
  };

  test('a resource from the verified bundle, under the sandbox policy', async () => {
    const state = await stateOf(tinyBundle());
    const answer = responseFor(state, { ...context, method: 'GET', pathname: '/app.js' });
    assert.equal(answer.status, 200);
    assert.equal(answer.headers['Content-Type'], 'text/javascript');
    assert.equal(answer.headers['Content-Security-Policy'], sandboxCsp(context));
    assert.equal(answer.headers['X-Content-Type-Options'], 'nosniff');
    assert.equal(answer.headers['Referrer-Policy'], 'no-referrer');
    assert.equal(answer.headers['X-Key-Web-Origin'], `key-web://${state.id}/`);
    assert.equal(Buffer.from(answer.body).toString(), 'export const tiny = true;\n');
  });

  test("the sandbox policy, not the bundle's own headers", async () => {
    const loose = tinyBundle({ headers: { 'content-security-policy': 'default-src *', 'access-control-allow-origin': '*', 'service-worker-allowed': '/' } });
    const answer = responseFor(await stateOf(loose), { ...context, method: 'GET', pathname: '/app.js' });
    assert.equal(answer.headers['Content-Security-Policy'], sandboxCsp(context));
    const names = Object.keys(answer.headers).map((name) => name.toLowerCase());
    assert.ok(!names.includes('access-control-allow-origin'));
    assert.ok(!names.includes('service-worker-allowed'));
  });

  test('the entry document exactly once per boot, and only into the frame the runner asked for', async () => {
    const state = await stateOf(tinyBundle());
    const boot = { ...context, method: 'GET', pathname: '/', destination: 'iframe', navigation: true };
    assert.equal(responseFor(state, { ...boot, armed: true }).status, 200);
    // Not asked for: an app navigating itself, or another app navigating a frame here.
    const refused = responseFor(state, { ...boot, armed: false });
    assert.equal(refused.status, 403);
    assert.match(refused.body, /not opened by KeyWeb Runner/);
    assert.equal(refused.headers['Content-Type'], 'text/plain; charset=utf-8');
    // As a page of its own, never, armed or not.
    assert.equal(responseFor(state, { ...boot, destination: 'document', armed: true }).status, 403);
  });

  test('nothing that is not in the bundle', async () => {
    const state = await stateOf(tinyBundle());
    for (const pathname of ['/missing.js', '/app.js/', '/APP.JS', '/../app.js', '//app.js', '/__keyweb/sw.js']) {
      assert.equal(responseFor(state, { ...context, method: 'GET', pathname }).status, 404, pathname);
    }
  });

  test('nothing at all without a verified bundle, and nothing to a method other than GET', async () => {
    for (const state of [null, undefined, {}, { id: 'x', exchanges: {} }]) {
      const answer = responseFor(state, { ...context, method: 'GET', pathname: '/' });
      assert.equal(answer.status, 409);
      assert.equal(answer.headers['Content-Security-Policy'], sandboxCsp(context));
    }
    const state = await stateOf(tinyBundle());
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']) assert.equal(responseFor(state, { ...context, method, pathname: '/app.js' }).status, 405);
    assert.equal(responseFor(state, { ...context, method: 'HEAD', pathname: '/app.js' }).status, 200);
  });

  test('headers are complete for every answer, including refusals', () => {
    const headers = sandboxHeaders({ id: 'x', runnerOrigin: RUNNER, contentType: 'text/plain' });
    assert.deepEqual(Object.keys(headers).sort(), ['Cache-Control', 'Content-Security-Policy', 'Content-Type', 'Cross-Origin-Resource-Policy', 'Permissions-Policy', 'Referrer-Policy', 'X-Content-Type-Options', 'X-Key-Web-Origin']);
  });
});

describe('the runner, the loader and the worker', () => {
  test('the runner may fetch from itself and the network port, and frame only key origins on its own port', () => {
    const policy = directives(runnerCsp({ appPort: 5760, mirrorPort: 5761 }));
    assert.equal(policy.get('default-src'), "'self'");
    assert.equal(policy.get('script-src'), "'self'");
    assert.equal(policy.get('style-src'), "'self'");
    assert.equal(policy.get('connect-src'), "'self' http://localhost:5761 http://*.localhost:5761");
    assert.equal(policy.get('frame-src'), 'http://*.localhost:5760');
    assert.equal(policy.get('frame-ancestors'), "'none'");
    assert.equal(policy.get('form-action'), "'none'");
    assert.equal(policy.get('require-trusted-types-for'), "'script'");
    assert.equal(policy.get('trusted-types'), "'none'");
    assert.ok(!runnerCsp({ appPort: 5760, mirrorPort: 5761 }).includes('unsafe'));
  });

  test('the loader requires Trusted Types and may create exactly one named policy', () => {
    const policy = directives(loaderCsp({ runnerOrigin: RUNNER }));
    assert.equal(policy.get('require-trusted-types-for'), "'script'");
    assert.equal(policy.get('trusted-types'), LOADER_POLICY_NAME);
    assert.equal(policy.get('default-src'), "'none'");
    assert.equal(policy.get('connect-src'), "'self'");
    assert.equal(policy.get('worker-src'), "'self'");
    assert.equal(policy.get('frame-ancestors'), RUNNER);
  });

  test('the worker cannot reach the network', () => {
    const policy = directives(WORKER_CSP);
    assert.equal(policy.get('connect-src'), "'none'");
    assert.equal(policy.get('default-src'), "'none'");
    assert.equal(policy.get('script-src'), "'self'");
  });

  test("the runner's own bundle carries a strict policy too", () => {
    const policy = directives(BUNDLE_CSP);
    assert.equal(policy.get('script-src'), "'self'");
    assert.equal(policy.get('require-trusted-types-for'), "'script'");
    assert.equal(policy.get('object-src'), "'none'");
  });

  test('origins are derived, never configured', () => {
    assert.equal(runnerOriginFrom({ protocol: 'http:', port: '5760' }), RUNNER);
    assert.equal(runnerOriginFrom({ protocol: 'https:', port: '' }), 'https://localhost');
    assert.equal(keyOriginUrl('abc', { port: '5760' }), 'http://abc.localhost:5760');
    assert.equal(keyOriginUrl('abc', { protocol: 'https:', port: '' }), 'https://abc.localhost');
  });
});
