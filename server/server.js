#!/usr/bin/env node
// Universal Clipboard relay + website. Zero dependencies.
//
// Accounts (email+password or Google) own an end-to-end encrypted clipboard. The server stores
// accounts, device sessions and ciphertext; it never sees a password, a vault key or clipboard text.
import { createHash, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { loadConfig } from './config.js';
import { cookie, createStatic, fail, parseCookies, readJson, securityHeaders, send } from './http.js';
import { createGoogle } from './google.js';
import { createLimiter } from './ratelimit.js';
import { createMailer, resetMail, verifyMail } from './mail.js';
import { buildOpenApi } from './openapi.js';
import { createStore } from './store.js';

const scryptAsync = promisify(scrypt);
const SESSION_COOKIE = 'uc_session';
const OAUTH_COOKIE = 'uc_oauth';
const PLATFORMS = new Set(['windows', 'linux', 'macos', 'android', 'ios', 'web', 'other']);
const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ23456789';

const sha256 = (s) => createHash('sha256').update(s).digest('hex');
const newToken = () => `uc_${randomBytes(32).toString('base64url')}`;
const isHex64 = (s) => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
const isEmail = (s) => typeof s === 'string' && s.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
const b64ish = (s, max) => typeof s === 'string' && s.length > 0 && s.length <= max && /^[A-Za-z0-9+/=]+$/.test(s);

function safeEqual(a, b) {
  return timingSafeEqual(createHash('sha256').update(String(a)).digest(), createHash('sha256').update(String(b)).digest());
}

async function hashAuth(authKey) {
  const salt = randomBytes(16);
  const hash = await scryptAsync(authKey, salt, 32, { N: 16384, r: 8, p: 1 });
  return { salt: salt.toString('hex'), hash: hash.toString('hex') };
}

const DUMMY_AUTH = await hashAuth('0'.repeat(64));
async function checkAuth(auth, authKey) {
  const a = auth ?? DUMMY_AUTH; // unknown users cost the same time as wrong passwords
  const got = await scryptAsync(authKey, Buffer.from(a.salt, 'hex'), 32, { N: 16384, r: 8, p: 1 });
  return timingSafeEqual(got, Buffer.from(a.hash, 'hex')) && auth !== null;
}

function cleanWrap(w, kinds) {
  if (!w || typeof w !== 'object' || !kinds.includes(w.kind) || !b64ish(w.nonce, 32) || !b64ish(w.ct, 256)) return null;
  return { kind: w.kind, nonce: w.nonce, ct: w.ct };
}

const cleanDevice = (v, fallback) => (typeof v === 'string' && v.trim() ? v.trim().replace(/[\u0000-\u001f]/g, '').slice(0, 64) : fallback);
const cleanPlatform = (v) => (PLATFORMS.has(v) ? v : 'other');

export function createRelay(opts = {}) {
  const cfg = loadConfig(opts);
  const store = createStore(cfg.dataDir);
  const limiter = createLimiter(cfg.rateLimit);
  const mailer = opts.mailer ?? createMailer(cfg);
  const google = createGoogle(cfg);
  const serveStatic = createStatic(cfg);
  const openapi = buildOpenApi(cfg);
  const originHost = new URL(cfg.publicUrl).host;

  /** userId -> Set<{ res, sessionId }> : open SSE streams */
  const listeners = new Map();
  /** codeHash -> pending device-approval request */
  const deviceRequests = new Map();
  /** ticket hash -> { userId, exp } : one-time Google sign-in handoff */
  const tickets = new Map();

  // ---------- helpers ----------
  const publicUser = (u) => ({ id: u.id, email: u.email, emailVerified: u.emailVerified, name: u.name || undefined, hasPassword: Boolean(u.auth), google: Boolean(u.googleSub) });
  const publicSession = (s, currentId) => ({
    id: s.id,
    device: s.device,
    platform: s.platform,
    client: s.client,
    createdAt: s.createdAt,
    lastSeen: s.lastSeen,
    expiresAt: s.expiresAt,
    current: s.id === currentId,
    online: [...(listeners.get(s.userId) ?? [])].some((l) => l.sessionId === s.id),
  });

  function clientIp(req) {
    if (cfg.trustProxy) {
      const xff = String(req.headers['x-forwarded-for'] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
      if (xff.length) return xff.at(-1);
    }
    return req.socket.remoteAddress ?? 'unknown';
  }

  /** Rate-limit helper. Sends 429 and returns true when the caller is over the limit. */
  function limited(req, res, key, max, windowMs) {
    const wait = limiter.hit(key, max, windowMs);
    if (!wait) return false;
    fail(res, 429, 'rate_limited', `too many requests, retry in ${wait}s`, { retryAfter: wait });
    return true;
  }

  function sessionCookie(token, maxAgeMs) {
    return cookie(SESSION_COOKIE, token, { maxAgeMs, secure: cfg.secureCookies });
  }

  const oauthCookie = (value, maxAgeMs) => cookie(OAUTH_COOKIE, value, { maxAgeMs, secure: cfg.secureCookies, sameSite: 'Lax', path: '/api/v1/auth/google' });

  function notifySessions(userId) {
    for (const l of listeners.get(userId) ?? []) l.res.write('event: sessions\ndata: {}\n\n');
  }

  function endSession(s, reason = 'revoked') {
    store.dropSession(s);
    for (const l of [...(listeners.get(s.userId) ?? [])]) {
      if (l.sessionId !== s.id) continue;
      listeners.get(s.userId).delete(l); // before end(), so the notify below never writes to a closed stream
      l.res.write(`event: session-ended\ndata: ${JSON.stringify({ reason })}\n\n`);
      l.res.end();
    }
    notifySessions(s.userId);
  }

  function createSession(user, { device, platform, client }) {
    const mine = store.sessionsOf(user.id).sort((a, b) => a.lastSeen - b.lastSeen);
    while (mine.length >= cfg.maxSessionsPerUser) endSession(mine.shift(), 'evicted');
    const token = newToken();
    const now = Date.now();
    const session = { id: randomBytes(8).toString('hex'), userId: user.id, hash: sha256(token), device, platform, client, createdAt: now, lastSeen: now, expiresAt: now + cfg.sessionTtlMs };
    store.putSession(session);
    notifySessions(user.id);
    return { token, session };
  }

  /** Create a session and send the standard sign-in response (cookie for the web app, token for devices). */
  function signedIn(res, status, user, info, extra = {}, alsoCookie) {
    const { token, session } = createSession(user, info);
    const headers = info.client === 'web' ? { 'set-cookie': [sessionCookie(token, cfg.sessionTtlMs), alsoCookie].filter(Boolean) } : {};
    return send(res, status, { user: publicUser(user), wrap: user.wrap, session: publicSession(session, session.id), ...(info.client === 'web' ? {} : { token }), ...extra }, headers);
  }

  const deviceInfo = (body) => ({
    device: cleanDevice(body.device, 'Unnamed device'),
    platform: cleanPlatform(body.platform),
    client: body.client === 'web' ? 'web' : 'cli',
  });

  function issueToken(type, userId, ttlMs) {
    const raw = randomBytes(32).toString('base64url');
    store.data.tokens[sha256(raw)] = { type, userId, exp: Date.now() + ttlMs };
    store.save();
    return raw;
  }
  function takeToken(type, raw, { consume = true } = {}) {
    if (typeof raw !== 'string' || raw.length > 100) return null;
    const h = sha256(raw);
    const t = store.data.tokens[h];
    if (!t || t.type !== type) return null;
    if (t.exp < Date.now()) {
      delete store.data.tokens[h];
      return null;
    }
    if (consume) {
      delete store.data.tokens[h];
      store.save();
    }
    return store.userById(t.userId) ?? null;
  }

  function sendMail(to, { subject, text }) {
    mailer.send({ to, subject, text }).catch((e) => console.error('mail failed:', e.message));
  }
  function sendVerification(user) {
    const token = issueToken('verify', user.id, 24 * 3600_000);
    sendMail(user.email, verifyMail(`${cfg.publicUrl}/verify#token=${token}`));
  }

  /** Authenticate via `Authorization: Bearer` (devices) or the session cookie (web). Sends 401 and returns null on failure. */
  function authenticate(req, res, { verified = false } = {}) {
    const bearer = /^Bearer (uc_[A-Za-z0-9_-]{20,64})$/.exec(req.headers.authorization ?? '');
    const cookieTok = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    const token = bearer?.[1] ?? (cookieTok && /^uc_[A-Za-z0-9_-]{20,64}$/.test(cookieTok) ? cookieTok : null);
    if (!token) return void fail(res, 401, 'unauthenticated', 'sign in required');
    const session = store.sessionByHash(sha256(token));
    const now = Date.now();
    if (!session || session.expiresAt < now) {
      if (session) endSession(session, 'expired');
      return void fail(res, 401, 'session_ended', 'this session has ended; sign in again', {}, bearer ? {} : { 'set-cookie': sessionCookie('', 0) });
    }
    if (!bearer) {
      // Cookie auth: defend against cross-site requests (SameSite=Strict is the first line, this is the second).
      if (!['GET', 'HEAD'].includes(req.method)) {
        const origin = req.headers.origin;
        let ok = req.headers['x-uc-csrf'] === '1';
        if (ok && origin) {
          try {
            ok = new URL(origin).host === (req.headers.host ?? originHost);
          } catch {
            ok = false;
          }
        }
        if (!ok) return void fail(res, 403, 'csrf', 'cross-site request blocked');
      }
    }
    const user = store.userById(session.userId);
    if (!user) return void fail(res, 401, 'session_ended', 'account no longer exists');
    if (now - session.lastSeen > 60_000) {
      session.lastSeen = now;
      session.expiresAt = now + cfg.sessionTtlMs;
      store.save();
      if (!bearer) res.setHeader('set-cookie', sessionCookie(token, cfg.sessionTtlMs));
    }
    if (verified && cfg.requireVerifiedEmail && !user.emailVerified) {
      return void fail(res, 403, 'email_not_verified', 'confirm your email address to use the clipboard');
    }
    return { user, session, viaCookie: !bearer };
  }

  function broadcast(userId, event, data) {
    for (const l of listeners.get(userId) ?? []) {
      l.res.write(`event: ${event}\n${event === 'item' ? `id: ${data.seq}\n` : ''}data: ${JSON.stringify(data)}\n\n`);
    }
  }

  function prune(v) {
    const cutoff = Date.now() - cfg.ttlMs;
    v.items = v.items.filter((i) => i.ts >= cutoff).slice(-cfg.maxItems);
    // Per-account storage ceiling: drop the oldest items first (always keep the newest one).
    let bytes = v.items.reduce((n, i) => n + i.ct.length + i.nonce.length + i.id.length, 0);
    while (bytes > cfg.maxVaultBytes && v.items.length > 1) {
      const gone = v.items.shift();
      bytes -= gone.ct.length + gone.nonce.length + gone.id.length;
    }
  }

  // Housekeeping: expired sessions/tokens/tickets/device requests, and items past their TTL.
  const janitor = setInterval(() => {
    const now = Date.now();
    for (const s of store.sweep(now)) for (const l of [...(listeners.get(s.userId) ?? [])]) if (l.sessionId === s.id) l.res.end();
    for (const [k, t] of tickets) if (t.exp < now) tickets.delete(k);
    for (const [k, r] of deviceRequests) if (r.exp < now) deviceRequests.delete(k);
    for (const v of Object.values(store.data.items)) prune(v);
    store.save();
  }, 10 * 60_000);
  janitor.unref();

  function resetVault(user) {
    const v = store.vault(user.id);
    const ids = v.items.map((i) => i.id);
    v.items = [];
    store.save();
    for (const id of ids) broadcast(user.id, 'delete', { id });
  }

  // ---------- auth routes ----------
  const routes = [];
  const route = (method, path, handler) => routes.push({ method, path, handler });

  route('GET', '/api/v1/auth/providers', (req, res) =>
    send(res, 200, { google: cfg.googleEnabled, signups: cfg.signups, inviteRequired: Boolean(cfg.inviteCode), emailVerification: cfg.requireVerifiedEmail }),
  );

  route('POST', '/api/v1/auth/signup', async (req, res) => {
    if (limited(req, res, `auth:${clientIp(req)}`, 20, 10 * 60_000)) return;
    const body = await readJson(req, res, 16_384);
    if (!body) return;
    if (!cfg.signups) return fail(res, 403, 'signups_closed', 'new sign-ups are closed on this server');
    if (cfg.inviteCode && !safeEqual(body.inviteCode ?? '', cfg.inviteCode)) return fail(res, 403, 'invite_required', 'a valid invite code is required');
    const email = String(body.email ?? '').trim().toLowerCase();
    const wrap = cleanWrap(body.wrap, ['password']);
    if (!isEmail(email) || !isHex64(body.authKey) || !wrap) return fail(res, 400, 'invalid_request', 'expected { email, authKey, wrap }');
    if (store.userByEmail(email)) return fail(res, 409, 'email_taken', 'an account with this email already exists');
    if (store.userCount() >= cfg.maxUsers) return fail(res, 403, 'server_full', 'this server is not accepting new accounts');
    const auth = await hashAuth(body.authKey);
    // Re-check after the await: concurrent signups for one address must not both succeed.
    if (store.userByEmail(email)) return fail(res, 409, 'email_taken', 'an account with this email already exists');
    if (store.userCount() >= cfg.maxUsers) return fail(res, 403, 'server_full', 'this server is not accepting new accounts');
    const user = { id: randomBytes(8).toString('hex'), email, emailVerified: false, createdAt: Date.now(), auth, googleSub: null, name: '', wrap };
    store.putUser(user);
    sendVerification(user);
    return signedIn(res, 201, user, deviceInfo(body));
  });

  route('POST', '/api/v1/auth/login', async (req, res) => {
    if (limited(req, res, `auth:${clientIp(req)}`, 30, 10 * 60_000)) return;
    const body = await readJson(req, res, 16_384);
    if (!body) return;
    const email = String(body.email ?? '').trim().toLowerCase();
    if (!isEmail(email) || !isHex64(body.authKey)) return fail(res, 400, 'invalid_request', 'expected { email, authKey }');
    // Per address+account (so a stranger cannot lock you out from elsewhere) and a looser per-account ceiling.
    const ipKey = `login:${clientIp(req)}:${email}`;
    if (limited(req, res, ipKey, 10, 15 * 60_000) || limited(req, res, `login:${email}`, 100, 15 * 60_000)) return;
    const user = store.userByEmail(email);
    if (!(await checkAuth(user?.auth ?? null, body.authKey))) return fail(res, 401, 'invalid_credentials', 'wrong email or password');
    limiter.clear(ipKey);
    return signedIn(res, 200, user, deviceInfo(body));
  });

  route('POST', '/api/v1/auth/logout', (req, res) => {
    const bearer = /^Bearer (uc_[A-Za-z0-9_-]{20,64})$/.exec(req.headers.authorization ?? '')?.[1];
    const tok = bearer ?? parseCookies(req.headers.cookie)[SESSION_COOKIE];
    const s = tok && store.sessionByHash(sha256(tok));
    if (s) endSession(s, 'logout');
    return send(res, 204, null, { 'set-cookie': sessionCookie('', 0) });
  });

  route('POST', '/api/v1/auth/verify', async (req, res) => {
    if (limited(req, res, `auth:${clientIp(req)}`, 30, 10 * 60_000)) return;
    const body = await readJson(req, res, 4096);
    if (!body) return;
    const user = takeToken('verify', body.token);
    if (!user) return fail(res, 400, 'invalid_token', 'this link is invalid or has expired');
    user.emailVerified = true;
    store.save();
    return send(res, 200, { user: publicUser(user) });
  });

  route('POST', '/api/v1/auth/verify/resend', (req, res) => {
    const ctx = authenticate(req, res);
    if (!ctx) return;
    if (limited(req, res, `resend:${ctx.user.id}`, 3, 3600_000)) return;
    if (!ctx.user.emailVerified) sendVerification(ctx.user);
    return send(res, 202, { sent: !ctx.user.emailVerified });
  });

  route('POST', '/api/v1/auth/forgot', async (req, res) => {
    if (limited(req, res, `forgot:${clientIp(req)}`, 5, 3600_000)) return;
    const body = await readJson(req, res, 4096);
    if (!body) return;
    const email = String(body.email ?? '').trim().toLowerCase();
    // Same answer whether or not the account exists, so this cannot be used to look up emails.
    if (isEmail(email) && !limiter.hit(`forgot-email:${email}`, 3, 3600_000)) {
      const user = store.userByEmail(email);
      if (user?.auth) sendMail(user.email, resetMail(`${cfg.publicUrl}/reset#token=${issueToken('reset', user.id, 3600_000)}`));
    }
    return send(res, 202, { ok: true });
  });

  route('POST', '/api/v1/auth/reset/inspect', async (req, res) => {
    if (limited(req, res, `auth:${clientIp(req)}`, 30, 10 * 60_000)) return;
    const body = await readJson(req, res, 4096);
    if (!body) return;
    const user = takeToken('reset', body.token, { consume: false });
    if (!user) return fail(res, 400, 'invalid_token', 'this link is invalid or has expired');
    return send(res, 200, { email: user.email });
  });

  route('POST', '/api/v1/auth/reset', async (req, res) => {
    if (limited(req, res, `auth:${clientIp(req)}`, 20, 10 * 60_000)) return;
    const body = await readJson(req, res, 16_384);
    if (!body) return;
    const wrap = cleanWrap(body.wrap, ['password']);
    if (!isHex64(body.authKey) || !wrap) return fail(res, 400, 'invalid_request', 'expected { token, authKey, wrap }');
    const user = takeToken('reset', body.token);
    if (!user) return fail(res, 400, 'invalid_token', 'this link is invalid or has expired');
    user.auth = await hashAuth(body.authKey);
    user.wrap = wrap;
    user.emailVerified = true; // they just proved control of the mailbox
    store.save();
    resetVault(user); // old items were encrypted under the lost key
    for (const s of store.sessionsOf(user.id)) endSession(s, 'password_reset');
    return send(res, 204);
  });

  // ---------- Google ----------
  route('GET', '/api/v1/auth/google/start', (req, res) => {
    if (!cfg.googleEnabled) return fail(res, 404, 'google_disabled', 'Google sign-in is not configured on this server');
    if (limited(req, res, `auth:${clientIp(req)}`, 30, 10 * 60_000)) return;
    const { url, state } = google.begin();
    res.writeHead(302, { location: url, 'cache-control': 'no-store', 'set-cookie': oauthCookie(state, 600_000) });
    res.end();
  });

  route('GET', '/api/v1/auth/google/callback', async (req, res, url) => {
    // The state cookie stays until the ticket is exchanged, which binds the ticket to the browser that started the flow.
    const back = (frag, { keepCookie = false } = {}) => {
      res.writeHead(302, { location: `/app#${frag}`, 'cache-control': 'no-store', ...(keepCookie ? {} : { 'set-cookie': oauthCookie('', 0) }) });
      res.end();
    };
    if (!cfg.googleEnabled) return back('error=google_disabled');
    const state = url.searchParams.get('state') ?? '';
    if (!state || parseCookies(req.headers.cookie)[OAUTH_COOKIE] !== state) return back('error=google_failed'); // not the browser that started it
    try {
      if (url.searchParams.get('error')) throw new Error(url.searchParams.get('error'));
      const g = await google.finish(state, url.searchParams.get('code'));
      let user = store.userByGoogle(g.sub);
      if (!user) {
        const existing = store.userByEmail(g.email);
        if (existing && existing.emailVerified) {
          // Same verified mailbox: link, but never re-point an account that already belongs to another Google identity.
          if (existing.googleSub) return back('error=google_failed');
          existing.googleSub = g.sub;
          existing.name ||= g.name;
          store.putUser(existing);
          user = existing;
        } else {
          if (!cfg.signups) return back('error=signups_closed');
          if (store.userCount() - (existing ? 1 : 0) >= cfg.maxUsers) return back('error=server_full');
          if (existing) store.dropUser(existing); // unverified squatter on this mailbox: Google proves ownership
          user = { id: randomBytes(8).toString('hex'), email: g.email, emailVerified: true, createdAt: Date.now(), auth: null, googleSub: g.sub, name: g.name, wrap: null };
          store.putUser(user);
        }
      }
      const ticket = randomBytes(24).toString('base64url');
      tickets.set(sha256(ticket), { userId: user.id, state, exp: Date.now() + 90_000 });
      return back(`ticket=${ticket}`, { keepCookie: true });
    } catch (e) {
      console.error('google sign-in failed:', e.message);
      return back('error=google_failed');
    }
  });

  route('POST', '/api/v1/auth/google/exchange', async (req, res) => {
    if (limited(req, res, `auth:${clientIp(req)}`, 30, 10 * 60_000)) return;
    const body = await readJson(req, res, 4096);
    if (!body) return;
    const h = sha256(String(body.ticket ?? ''));
    const t = tickets.get(h);
    tickets.delete(h);
    const bound = t && parseCookies(req.headers.cookie)[OAUTH_COOKIE] === t.state; // same browser that started the flow
    const user = bound && t.exp > Date.now() ? store.userById(t.userId) : null;
    if (!user) return fail(res, 400, 'invalid_ticket', 'sign-in expired; try again', {}, { 'set-cookie': oauthCookie('', 0) });
    return signedIn(res, 200, user, deviceInfo({ ...body, client: 'web' }), {}, oauthCookie('', 0));
  });

  // ---------- account ----------
  route('GET', '/api/v1/account', (req, res) => {
    const ctx = authenticate(req, res);
    if (!ctx) return;
    return send(res, 200, { user: publicUser(ctx.user), wrap: ctx.user.wrap, session: publicSession(ctx.session, ctx.session.id) });
  });

  route('POST', '/api/v1/account/key', async (req, res) => {
    const ctx = authenticate(req, res);
    if (!ctx) return;
    if (limited(req, res, `pw:${ctx.user.id}`, 10, 15 * 60_000)) return;
    const body = await readJson(req, res, 4096);
    if (!body) return;
    const wrap = cleanWrap(body.wrap, ['passphrase']);
    if (!wrap || !isHex64(body.authKey)) return fail(res, 400, 'invalid_request', 'expected { wrap (kind "passphrase"), authKey }');
    const { user } = ctx;
    if (user.auth) return fail(res, 409, 'has_password', 'this account encrypts with its password; use /account/password');
    // First-time setup is open to the signed-in session; replacing an existing key needs proof of the old passphrase,
    // so a stolen session cannot lock the owner out of their own clipboard.
    if (user.wrap && !(isHex64(body.oldAuthKey) && (await checkAuth(user.keyAuth ?? null, body.oldAuthKey)))) return fail(res, 401, 'invalid_credentials', 'current passphrase is wrong');
    user.keyAuth = await hashAuth(body.authKey);
    user.wrap = wrap;
    store.save();
    return send(res, 204);
  });

  route('POST', '/api/v1/account/password', async (req, res) => {
    const ctx = authenticate(req, res);
    if (!ctx) return;
    if (limited(req, res, `pw:${ctx.user.id}`, 10, 15 * 60_000)) return;
    const body = await readJson(req, res, 16_384);
    if (!body) return;
    const wrap = cleanWrap(body.wrap, ['password']);
    if (!isHex64(body.authKey) || !isHex64(body.newAuthKey) || !wrap) return fail(res, 400, 'invalid_request', 'expected { authKey, newAuthKey, wrap }');
    if (!ctx.user.auth) return fail(res, 409, 'no_password', 'this account has no password');
    if (!(await checkAuth(ctx.user.auth, body.authKey))) return fail(res, 401, 'invalid_credentials', 'current password is wrong');
    ctx.user.auth = await hashAuth(body.newAuthKey);
    ctx.user.wrap = wrap;
    store.save();
    for (const s of store.sessionsOf(ctx.user.id)) if (s.id !== ctx.session.id) endSession(s, 'password_changed');
    return send(res, 204);
  });

  route('POST', '/api/v1/account/delete', async (req, res) => {
    const ctx = authenticate(req, res);
    if (!ctx) return;
    if (limited(req, res, `pw:${ctx.user.id}`, 10, 15 * 60_000)) return;
    const body = await readJson(req, res, 4096);
    if (!body) return;
    if (String(body.confirmEmail ?? '').trim().toLowerCase() !== ctx.user.email) return fail(res, 400, 'confirm_email', 'type your email address to confirm');
    const proof = ctx.user.auth ?? ctx.user.keyAuth;
    if (proof && !(isHex64(body.authKey) && (await checkAuth(proof, body.authKey)))) return fail(res, 401, 'invalid_credentials', 'password or passphrase is wrong');
    for (const s of store.sessionsOf(ctx.user.id)) endSession(s, 'account_deleted');
    store.dropUser(ctx.user);
    return send(res, 204, null, { 'set-cookie': sessionCookie('', 0) });
  });

  route('GET', '/api/v1/sessions', (req, res) => {
    const ctx = authenticate(req, res);
    if (!ctx) return;
    const list = store.sessionsOf(ctx.user.id).sort((a, b) => b.lastSeen - a.lastSeen).map((s) => publicSession(s, ctx.session.id));
    return send(res, 200, { sessions: list });
  });

  route('DELETE', '/api/v1/sessions', (req, res) => {
    const ctx = authenticate(req, res);
    if (!ctx) return;
    for (const s of store.sessionsOf(ctx.user.id)) if (s.id !== ctx.session.id) endSession(s, 'revoked');
    return send(res, 204);
  });

  route('DELETE', /^\/api\/v1\/sessions\/([0-9a-f]{16})$/, (req, res, url, m) => {
    const ctx = authenticate(req, res);
    if (!ctx) return;
    const s = store.data.sessions[m[1]];
    if (!s || s.userId !== ctx.user.id) return fail(res, 404, 'not_found', 'no such session');
    endSession(s, s.id === ctx.session.id ? 'logout' : 'revoked');
    return send(res, 204, null, s.id === ctx.session.id ? { 'set-cookie': sessionCookie('', 0) } : {});
  });

  // ---------- device approval (CLI / headless devices) ----------
  const newUserCode = () => {
    let c = '';
    for (const b of randomBytes(8)) c += USER_CODE_ALPHABET[b % USER_CODE_ALPHABET.length];
    return `${c.slice(0, 4)}-${c.slice(4)}`;
  };
  const sweepDevices = () => {
    const now = Date.now();
    for (const [k, r] of deviceRequests) if (r.exp < now) deviceRequests.delete(k);
  };
  const requestByUserCode = (code) => {
    const norm = String(code ?? '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    for (const r of deviceRequests.values()) if (r.userCode.replace('-', '') === norm && r.exp > Date.now()) return r;
    return null;
  };

  route('POST', '/api/v1/device/start', async (req, res) => {
    if (limited(req, res, `device:${clientIp(req)}`, 20, 10 * 60_000)) return;
    const body = await readJson(req, res, 4096);
    if (!body) return;
    if (!b64ish(body.pub, 200)) return fail(res, 400, 'invalid_request', 'expected { device, platform, pub }');
    sweepDevices();
    if (deviceRequests.size > 2000) return fail(res, 503, 'busy', 'too many pending device requests');
    const deviceCode = randomBytes(32).toString('base64url');
    const r = { userCode: newUserCode(), device: cleanDevice(body.device, 'Unnamed device'), platform: cleanPlatform(body.platform), pub: body.pub, exp: Date.now() + 10 * 60_000, status: 'pending' };
    deviceRequests.set(sha256(deviceCode), r);
    return send(res, 201, { deviceCode, userCode: r.userCode, verificationUrl: `${cfg.publicUrl}/device?code=${r.userCode}`, expiresIn: 600, interval: 2 });
  });

  route('POST', '/api/v1/device/token', async (req, res) => {
    if (limited(req, res, `device-poll:${clientIp(req)}`, 600, 10 * 60_000)) return;
    const body = await readJson(req, res, 4096);
    if (!body) return;
    const h = sha256(String(body.deviceCode ?? ''));
    const r = deviceRequests.get(h);
    if (!r || r.exp < Date.now()) return fail(res, 400, 'expired_token', 'this sign-in request expired; start again');
    if (r.status === 'denied') {
      deviceRequests.delete(h);
      return fail(res, 400, 'access_denied', 'the request was denied');
    }
    if (r.status !== 'approved') return fail(res, 400, 'authorization_pending', 'waiting for approval');
    deviceRequests.delete(h);
    const user = store.userById(r.userId);
    const s = r.sessionId && store.data.sessions[r.sessionId];
    if (!user || !s) return fail(res, 400, 'expired_token', 'the approving session ended; start again');
    return send(res, 200, { token: r.token, user: publicUser(user), session: publicSession(s, s.id), sealed: r.sealed });
  });

  route('POST', '/api/v1/device/lookup', async (req, res) => {
    const ctx = authenticate(req, res, { verified: true });
    if (!ctx) return;
    if (limited(req, res, `lookup:${ctx.user.id}`, 15, 10 * 60_000)) return;
    const body = await readJson(req, res, 4096);
    if (!body) return;
    const r = requestByUserCode(body.userCode);
    if (!r || r.status !== 'pending') return fail(res, 404, 'not_found', 'no pending request with that code');
    return send(res, 200, { userCode: r.userCode, device: r.device, platform: r.platform, pub: r.pub });
  });

  route('POST', '/api/v1/device/approve', async (req, res) => {
    const ctx = authenticate(req, res, { verified: true });
    if (!ctx) return;
    if (limited(req, res, `lookup:${ctx.user.id}`, 15, 10 * 60_000)) return;
    const body = await readJson(req, res, 8192);
    if (!body) return;
    const r = requestByUserCode(body.userCode);
    if (!r || r.status !== 'pending') return fail(res, 404, 'not_found', 'no pending request with that code');
    if (body.deny === true) {
      r.status = 'denied';
      return send(res, 204);
    }
    const sealed = body.sealed;
    if (!sealed || !b64ish(sealed.pub, 200) || !b64ish(sealed.nonce, 32) || !b64ish(sealed.ct, 256)) return fail(res, 400, 'invalid_request', 'expected { userCode, sealed }');
    const { token, session } = createSession(ctx.user, { device: r.device, platform: r.platform, client: 'cli' });
    Object.assign(r, { status: 'approved', userId: ctx.user.id, sessionId: session.id, token, sealed: { pub: sealed.pub, nonce: sealed.nonce, ct: sealed.ct } });
    return send(res, 204);
  });

  // ---------- clipboard items ----------
  route('POST', '/api/v1/items', async (req, res) => {
    const ctx = authenticate(req, res, { verified: true });
    if (!ctx) return;
    if (limited(req, res, `items:${ctx.session.id}`, 240, 60_000)) return;
    const body = await readJson(req, res, cfg.maxBodyBytes);
    if (!body) return;
    const v = store.vault(ctx.user.id);
    const { id, nonce, ct } = body;
    if (![id, nonce, ct].every((s) => typeof s === 'string' && s.length > 0 && s.length <= cfg.maxBodyBytes) || id.length > 64) {
      return fail(res, 400, 'invalid_request', 'expected {id, nonce, ct} strings');
    }
    const dup = v.items.find((i) => i.id === id);
    if (dup) return send(res, 200, dup);
    const item = { id, seq: v.nextSeq++, ts: Date.now(), nonce, ct };
    v.items.push(item);
    prune(v);
    store.save();
    broadcast(ctx.user.id, 'item', item);
    return send(res, 201, item);
  });

  route('GET', '/api/v1/items', (req, res, url) => {
    const ctx = authenticate(req, res, { verified: true });
    if (!ctx) return;
    const v = store.vault(ctx.user.id);
    prune(v);
    const since = Number(url.searchParams.get('since') ?? 0) || 0;
    return send(res, 200, { items: v.items.filter((i) => i.seq > since), lastSeq: v.nextSeq - 1 });
  });

  route('DELETE', '/api/v1/items', (req, res) => {
    const ctx = authenticate(req, res, { verified: true });
    if (!ctx) return;
    resetVault(ctx.user);
    return send(res, 204);
  });

  route('DELETE', /^\/api\/v1\/items\/([^/]+)$/, (req, res, url, m) => {
    const ctx = authenticate(req, res, { verified: true });
    if (!ctx) return;
    const id = decodeURIComponent(m[1]);
    const v = store.vault(ctx.user.id);
    const before = v.items.length;
    v.items = v.items.filter((i) => i.id !== id);
    if (v.items.length !== before) {
      store.save();
      broadcast(ctx.user.id, 'delete', { id });
    }
    return send(res, 204);
  });

  route('GET', '/api/v1/events', (req, res, url) => {
    const ctx = authenticate(req, res, { verified: true });
    if (!ctx) return;
    if ((listeners.get(ctx.user.id)?.size ?? 0) >= 20) return fail(res, 429, 'too_many_streams', 'too many open connections for this account');
    const v = store.vault(ctx.user.id);
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive', 'x-accel-buffering': 'no' });
    res.write(': connected\n\n');
    prune(v);
    const since = Number(req.headers['last-event-id'] ?? url.searchParams.get('since') ?? 0) || 0;
    for (const item of v.items.filter((i) => i.seq > since)) {
      res.write(`event: item\nid: ${item.seq}\ndata: ${JSON.stringify(item)}\n\n`);
    }
    const entry = { res, sessionId: ctx.session.id };
    if (!listeners.has(ctx.user.id)) listeners.set(ctx.user.id, new Set());
    listeners.get(ctx.user.id).add(entry);
    notifySessions(ctx.user.id);
    const ping = setInterval(() => {
      if (!store.data.sessions[ctx.session.id] || ctx.session.expiresAt < Date.now()) {
        endSession(ctx.session, 'expired');
        return;
      }
      res.write(': ping\n\n');
    }, 25_000);
    req.on('close', () => {
      clearInterval(ping);
      listeners.get(ctx.user.id)?.delete(entry);
      notifySessions(ctx.user.id);
    });
  });

  route('GET', '/api/v1/openapi.json', (req, res) => send(res, 200, openapi, { 'cache-control': 'public, max-age=300' }));

  // ---------- server ----------
  async function handleApi(req, res, url) {
    if (limited(req, res, `api:${clientIp(req)}`, 600, 60_000)) return;
    for (const r of routes) {
      if (r.method !== req.method) continue;
      const m = typeof r.path === 'string' ? (r.path === url.pathname ? [] : null) : r.path.exec(url.pathname);
      if (m) return r.handler(req, res, url, m);
    }
    const pathKnown = routes.some((r) => (typeof r.path === 'string' ? r.path === url.pathname : r.path.test(url.pathname)));
    return pathKnown ? fail(res, 405, 'method_not_allowed', 'method not allowed') : fail(res, 404, 'not_found', 'not found');
  }

  const server = createServer(async (req, res) => {
    securityHeaders(res, cfg);
    try {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname === '/healthz') return send(res, 200, { ok: true });
      if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
      return await serveStatic(req, res, url);
    } catch (err) {
      console.error(err);
      if (!res.headersSent) fail(res, 500, 'internal', 'internal error');
      else res.end();
    }
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 15_000;

  server.on('close', () => {
    clearInterval(janitor);
    store.close();
    limiter.stop();
  });

  server.relay = { mailer, store, config: cfg };
  return server;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 8787);
  const host = process.env.HOST ?? '127.0.0.1';
  const server = createRelay();
  const cfg = server.relay.config;
  server.listen(port, host, () => {
    console.log(`Universal Clipboard listening on http://${host}:${port} (public URL ${cfg.publicUrl})`);
    console.log(`  google sign-in: ${cfg.googleEnabled ? 'on' : 'off (set UC_GOOGLE_CLIENT_ID / UC_GOOGLE_CLIENT_SECRET)'}`);
    console.log(`  email delivery: ${cfg.mail.resendApiKey ? 'resend' : 'off, links are printed to this console (set UC_RESEND_API_KEY)'}`);
    console.log(`  email verification required: ${cfg.requireVerifiedEmail}`);
  });
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => server.close(() => process.exit(0)).closeAllConnections());
}
