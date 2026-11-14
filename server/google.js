// Google sign-in: OAuth 2.0 authorization-code flow with PKCE, run entirely on the server so the page
// needs no third-party script (keeps the CSP strict). The id_token comes straight from Google's token
// endpoint over TLS, so per Google's guidance it needs no separate signature check; we still validate
// audience, issuer, expiry and email_verified.
import { createHash, randomBytes } from 'node:crypto';

const b64u = (buf) => Buffer.from(buf).toString('base64url');

export function createGoogle(cfg) {
  const pending = new Map(); // state -> { verifier, exp }

  function sweep() {
    const now = Date.now();
    for (const [k, v] of pending) if (v.exp < now) pending.delete(k);
  }

  const redirectUri = () => `${cfg.publicUrl}/api/v1/auth/google/callback`;

  return {
    redirectUri,

    /** Returns { url, state } to redirect the browser to. */
    begin() {
      sweep();
      if (pending.size > 5000) throw new Error('too many pending sign-ins');
      const state = b64u(randomBytes(18));
      const verifier = b64u(randomBytes(32));
      pending.set(state, { verifier, exp: Date.now() + 10 * 60_000 });
      const q = new URLSearchParams({
        client_id: cfg.google.clientId,
        redirect_uri: redirectUri(),
        response_type: 'code',
        scope: 'openid email profile',
        state,
        code_challenge: b64u(createHash('sha256').update(verifier).digest()),
        code_challenge_method: 'S256',
        prompt: 'select_account',
      });
      return { url: `${cfg.google.authUrl}?${q}`, state };
    },

    /** Validate the callback and return { sub, email, name }. Throws on any problem. */
    async finish(state, code) {
      const p = pending.get(state);
      pending.delete(state);
      if (!p || p.exp < Date.now() || !code) throw new Error('invalid or expired sign-in attempt');
      const res = await fetch(cfg.google.tokenUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: cfg.google.clientId,
          client_secret: cfg.google.clientSecret,
          redirect_uri: redirectUri(),
          grant_type: 'authorization_code',
          code_verifier: p.verifier,
        }),
      });
      if (!res.ok) throw new Error(`google token endpoint -> ${res.status}`);
      const { id_token: idToken } = await res.json();
      const claims = JSON.parse(Buffer.from(String(idToken).split('.')[1] ?? '', 'base64url').toString('utf8'));
      if (claims.aud !== cfg.google.clientId) throw new Error('id_token audience mismatch');
      if (!['https://accounts.google.com', 'accounts.google.com'].includes(claims.iss)) throw new Error('id_token issuer mismatch');
      if (!(claims.exp * 1000 > Date.now())) throw new Error('id_token expired');
      if (!claims.sub || !claims.email || claims.email_verified !== true) throw new Error('google account email is not verified');
      return { sub: String(claims.sub), email: String(claims.email).trim().toLowerCase(), name: claims.name ? String(claims.name).slice(0, 100) : '' };
    },
  };
}
