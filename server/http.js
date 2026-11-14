// HTTP plumbing: security headers, JSON helpers, cookies, static files (with ETag + gzip).
import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { gzip } from 'node:zlib';
import { promisify } from 'node:util';
import { ROOT } from './config.js';

const gzipAsync = promisify(gzip);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.webmanifest': 'application/manifest+json',
  '.json': 'application/json',
  '.png': 'image/png',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
  '.sh': 'text/plain; charset=utf-8',
  '.ps1': 'text/plain; charset=utf-8',
};
const COMPRESSIBLE = new Set(['.html', '.js', '.css', '.svg', '.webmanifest', '.json', '.txt', '.xml', '.sh', '.ps1']);
const TEMPLATED = new Set(['.html', '.txt', '.xml', '.webmanifest', '.json', '.sh', '.ps1']);

export const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "font-src 'self'",
  "manifest-src 'self'",
  "worker-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

export function securityHeaders(res, cfg) {
  res.setHeader('content-security-policy', CSP);
  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('x-frame-options', 'DENY');
  res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader('cross-origin-opener-policy', 'same-origin');
  res.setHeader('cross-origin-resource-policy', 'same-origin');
  res.setHeader('permissions-policy', 'clipboard-read=(self), clipboard-write=(self), camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  if (cfg.secureCookies) res.setHeader('strict-transport-security', 'max-age=63072000; includeSubDomains; preload');
}

export function send(res, status, body, extraHeaders = {}) {
  if (status === 204) {
    res.writeHead(204, extraHeaders);
    return res.end();
  }
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extraHeaders });
  res.end(JSON.stringify(body));
}

export const fail = (res, status, code, message, extra = {}, headers = {}) => send(res, status, { error: code, message, ...extra }, headers);

export async function readJson(req, res, maxBytes) {
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > maxBytes) {
      fail(res, 413, 'too_large', 'request body too large');
      req.destroy();
      return null;
    }
    chunks.push(c);
  }
  try {
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
    if (body && typeof body === 'object' && !Array.isArray(body)) return body;
  } catch {}
  fail(res, 400, 'invalid_json', 'expected a JSON object body');
  return null;
}

export function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

export function cookie(name, value, { maxAgeMs, secure, sameSite = 'Strict', path = '/' }) {
  return `${name}=${value}; Path=${path}; HttpOnly; SameSite=${sameSite}${secure ? '; Secure' : ''}${maxAgeMs !== undefined ? `; Max-Age=${Math.floor(maxAgeMs / 1000)}` : ''}`;
}

// --- Static files
const PAGES = {
  '/': 'index.html',
  '/privacy': 'privacy.html',
  '/terms': 'terms.html',
  '/docs': 'docs.html',
  '/security': 'security.html',
  '/favicon.ico': 'favicon.svg',
};
// The signed-in application (single page). Never indexed.
const APP_ROUTES = new Set(['/app', '/login', '/signup', '/forgot', '/reset', '/verify', '/device']);

export function createStatic(cfg) {
  const cache = new Map(); // file -> { mtimeMs, body, gz, etag }

  async function load(file, ext) {
    const st = await stat(file);
    let hit = cache.get(file);
    if (hit && hit.mtimeMs === st.mtimeMs) return hit;
    let body = await readFile(file);
    if (TEMPLATED.has(ext)) body = Buffer.from(body.toString('utf8').replaceAll('{{ORIGIN}}', cfg.publicUrl));
    hit = {
      mtimeMs: st.mtimeMs,
      body,
      gz: COMPRESSIBLE.has(ext) && body.length > 512 ? await gzipAsync(body) : null,
      etag: `"${createHash('sha1').update(body).digest('base64url').slice(0, 22)}"`,
    };
    cache.set(file, hit);
    return hit;
  }

  async function serveFile(req, res, file, status = 200) {
    const ext = extname(file);
    const hit = await load(file, ext);
    const headers = {
      'content-type': MIME[ext] ?? 'application/octet-stream',
      'cache-control': ext === '.png' || ext === '.svg' ? 'public, max-age=86400' : 'no-cache',
      etag: hit.etag,
      vary: 'accept-encoding',
    };
    if (APP_ROUTES_FILES.has(file)) headers['x-robots-tag'] = 'noindex, nofollow';
    if (status === 200 && req.headers['if-none-match'] === hit.etag) {
      res.writeHead(304, headers);
      return res.end();
    }
    let body = hit.body;
    if (hit.gz && /\bgzip\b/.test(req.headers['accept-encoding'] ?? '')) {
      body = hit.gz;
      headers['content-encoding'] = 'gzip';
    }
    headers['content-length'] = body.length;
    res.writeHead(status, headers);
    res.end(req.method === 'HEAD' ? undefined : body);
  }

  const WEB = join(ROOT, 'web');
  const SHARED = join(ROOT, 'shared');
  const CLI = join(ROOT, 'cli');
  const APP_ROUTES_FILES = new Set([join(WEB, 'app.html'), join(WEB, '404.html')]);

  return async function handleStatic(req, res, url) {
    if (req.method !== 'GET' && req.method !== 'HEAD') return fail(res, 405, 'method_not_allowed', 'method not allowed', { allow: 'GET, HEAD' });
    let pathname;
    try {
      pathname = decodeURIComponent(url.pathname);
    } catch {
      return notFound();
    }
    if (pathname.length > 1) pathname = pathname.replace(/\/+$/, '');

    let file;
    if (APP_ROUTES.has(pathname)) file = join(WEB, 'app.html');
    else if (PAGES[pathname]) file = join(WEB, PAGES[pathname]);
    else if (pathname.startsWith('/shared/')) file = join(SHARED, pathname.slice('/shared/'.length));
    else if (pathname.startsWith('/dl/shared/')) file = join(SHARED, pathname.slice('/dl/shared/'.length));
    else if (pathname.startsWith('/dl/cli/')) file = join(CLI, pathname.slice('/dl/cli/'.length));
    else file = join(WEB, pathname);

    file = normalize(file);
    const base = file.startsWith(SHARED + sep) ? SHARED : file.startsWith(CLI + sep) ? CLI : WEB;
    const rel = file.slice(base.length + 1);
    // Only files inside web/ or shared/; no dotfiles except /.well-known/
    const hidden = rel.split(sep).some((seg) => seg.startsWith('.') && seg !== '.well-known');
    if (!file.startsWith(base + sep) || hidden || /\.html$/.test(pathname) && !PAGES[pathname]) return notFound();
    try {
      return await serveFile(req, res, file);
    } catch {
      return notFound();
    }

    async function notFound() {
      try {
        return await serveFile(req, res, join(WEB, '404.html'), 404);
      } catch {
        return fail(res, 404, 'not_found', 'not found');
      }
    }
  };
}
