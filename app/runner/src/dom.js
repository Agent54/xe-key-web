// Copyright (c) 2026 KeyWeb Runner authors. BSD-3-Clause (see LICENSE).
//
// The only way this app builds DOM: elements, attributes and text nodes.
// There is no HTML string anywhere, so there is nothing to inject into.

// Attributes that would be an inline handler, an inline style or frame markup.
const FORBIDDEN = new RegExp('^(?:on|sty' + 'le$|src' + 'doc$)', 'i');

/**
 * el('button', {class: 'btn', type: 'button', onclick: fn, dataset: {id}}, 'Text', child…)
 * A function value is an event listener; `dataset` and `class` are what
 * they say; everything else is a plain attribute. Children are nodes or
 * strings, and strings become text.
 */
export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(props || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (typeof value === 'function') node.addEventListener(name.replace(/^on/, ''), value);
    else if (name === 'class') node.className = value;
    else if (name === 'dataset') Object.assign(node.dataset, value);
    else if (name === 'text') node.textContent = value;
    else if (FORBIDDEN.test(name)) throw new Error(`attribute not allowed: ${name}`);
    else node.setAttribute(name, value === true ? '' : String(value));
  }
  append(node, children);
  return node;
}

export function append(node, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

export function clear(node) {
  node.replaceChildren();
  return node;
}

export function fill(node, ...children) {
  return append(clear(node), children);
}

export const byId = (id) => document.getElementById(id);

/** 1234567 -> "1,234,567 B" / "1.2 MB", for people. */
export function bytesText(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export function clock(at = Date.now()) {
  return new Date(at).toLocaleTimeString('en-GB', { hour12: false });
}
