// Small DOM helpers. Everything is built with DOM APIs (never innerHTML): clipboard text is untrusted input.

/** h('div', { class: 'x', onclick: fn, text: 'hi' }, child, 'text') */
export function h(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else if (k in n && k !== 'list') n[k] = v;
    else n.setAttribute(k, v === true ? '' : v);
  }
  n.append(...kids.flat().filter((c) => c !== undefined && c !== null && c !== false));
  return n;
}

export const $ = (sel, root = document) => root.querySelector(sel);

export function toast(msg, ms = 2200) {
  const host = document.getElementById('toasts');
  const t = h('div', { class: 'toast', text: msg });
  host.append(t);
  setTimeout(() => t.remove(), ms);
}

/** Opens a modal. Returns { close, el }. Escape and a click on the backdrop close it. */
export function modal(...content) {
  const prev = document.activeElement;
  const box = h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true' }, ...content);
  const overlay = h('div', { class: 'overlay' }, box);
  const close = () => {
    overlay.remove();
    document.removeEventListener('keydown', onKey);
    prev?.focus?.();
  };
  const onKey = (e) => e.key === 'Escape' && close();
  overlay.addEventListener('mousedown', (e) => e.target === overlay && close());
  document.addEventListener('keydown', onKey);
  document.body.append(overlay);
  (box.querySelector('input, textarea, button') ?? box).focus();
  return { close, el: box };
}

export const GLYPHS = { windows: '🪟', linux: '🐧', macos: '🍎', android: '🤖', ios: '📱', web: '🌐', other: '💻' };
export const glyph = (platform) => GLYPHS[platform] ?? GLYPHS.other;

export function relTime(ts) {
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 10) return 'now';
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

export function platformOf(ua = navigator.userAgent) {
  return /Android/.test(ua) ? 'android' : /iPhone|iPad/.test(ua) ? 'ios' : /Windows/.test(ua) ? 'windows' : /Mac/.test(ua) ? 'macos' : /Linux|X11/.test(ua) ? 'linux' : 'other';
}

/** "Chrome on Windows" */
export function deviceName(ua = navigator.userAgent) {
  const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = { windows: 'Windows', linux: 'Linux', macos: 'macOS', android: 'Android', ios: 'iOS', other: 'device' }[platformOf(ua)];
  return `${browser} on ${os}`;
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = Object.assign(document.createElement('textarea'), { value: text });
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  }
}

const SVG = 'http://www.w3.org/2000/svg';
export function googleLogo() {
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('viewBox', '0 0 48 48');
  svg.setAttribute('class', 'google-g');
  svg.setAttribute('aria-hidden', 'true');
  for (const [fill, d] of [
    ['#EA4335', 'M24 9.5c3.5 0 6.6 1.2 9.1 3.6l6.8-6.8C35.8 2.4 30.3 0 24 0 14.6 0 6.5 5.4 2.6 13.2l7.9 6.1C12.4 13.6 17.7 9.5 24 9.5z'],
    ['#4285F4', 'M46.5 24.5c0-1.6-.1-3.1-.4-4.5H24v9h12.7c-.6 3-2.3 5.5-4.8 7.2l7.6 5.9c4.4-4.1 7-10.1 7-17.6z'],
    ['#FBBC05', 'M10.5 28.7c-.5-1.5-.8-3-.8-4.7s.3-3.2.8-4.7l-7.9-6.1C.9 16.4 0 20.1 0 24s.9 7.6 2.6 10.8l7.9-6.1z'],
    ['#34A853', 'M24 48c6.5 0 11.9-2.1 15.9-5.8l-7.6-5.9c-2.1 1.4-4.9 2.3-8.3 2.3-6.3 0-11.6-4.1-13.5-9.8l-7.9 6.1C6.5 42.6 14.6 48 24 48z'],
  ]) {
    const p = document.createElementNS(SVG, 'path');
    p.setAttribute('fill', fill);
    p.setAttribute('d', d);
    svg.append(p);
  }
  return svg;
}
