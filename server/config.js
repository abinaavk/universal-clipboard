// Runtime configuration. Everything comes from UC_* environment variables; `opts` (tests) wins over the environment.
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const DEFAULT_ORIGIN = 'https://uclip.gaiasentinel.online';

const truthy = (v) => /^(1|true|yes|on)$/i.test(String(v ?? ''));

export function loadConfig(opts = {}) {
  const env = process.env;
  const pick = (key, envName, fallback) => opts[key] ?? env[envName] ?? fallback;

  const publicUrl = String(pick('publicUrl', 'UC_PUBLIC_URL', DEFAULT_ORIGIN)).replace(/\/+$/, '');
  const mailKey = pick('resendApiKey', 'UC_RESEND_API_KEY', '');
  const cfg = {
    publicUrl,
    secureCookies: publicUrl.startsWith('https://'),
    dataDir: pick('dataDir', 'UC_DATA_DIR', join(ROOT, 'data')),
    trustProxy: opts.trustProxy ?? truthy(env.UC_TRUST_PROXY),

    // Clipboard retention
    maxItems: Number(pick('maxItems', 'UC_MAX_ITEMS', 100)),
    ttlMs: Number(pick('ttlHours', 'UC_TTL_HOURS', 24 * 7)) * 3600_000,
    maxBodyBytes: Number(pick('maxBodyBytes', 'UC_MAX_BODY_BYTES', 1_000_000)),
    maxVaultBytes: Number(pick('maxVaultBytes', 'UC_MAX_VAULT_BYTES', 5_000_000)),

    // Accounts
    signups: String(pick('signups', 'UC_SIGNUPS', 'open')) !== 'closed',
    inviteCode: pick('inviteCode', 'UC_INVITE_CODE', ''),
    maxUsers: Number(pick('maxUsers', 'UC_MAX_USERS', 10_000)),
    maxSessionsPerUser: Number(pick('maxSessionsPerUser', 'UC_MAX_SESSIONS', 25)),
    sessionTtlMs: Number(pick('sessionTtlDays', 'UC_SESSION_TTL_DAYS', 30)) * 86400_000,

    // Email (Resend). Without a key, mails are only logged to the console.
    mail: {
      resendApiKey: mailKey,
      from: pick('mailFrom', 'UC_MAIL_FROM', 'Universal Clipboard <no-reply@gaiasentinel.online>'),
      apiUrl: pick('mailApiUrl', 'UC_MAIL_API_URL', 'https://api.resend.com/emails'),
    },

    // Google sign-in (OAuth authorization-code flow with PKCE, handled server-side)
    google: {
      clientId: pick('googleClientId', 'UC_GOOGLE_CLIENT_ID', ''),
      clientSecret: pick('googleClientSecret', 'UC_GOOGLE_CLIENT_SECRET', ''),
      authUrl: pick('googleAuthUrl', 'UC_GOOGLE_AUTH_URL', 'https://accounts.google.com/o/oauth2/v2/auth'),
      tokenUrl: pick('googleTokenUrl', 'UC_GOOGLE_TOKEN_URL', 'https://oauth2.googleapis.com/token'),
    },

    rateLimit: opts.rateLimit ?? !truthy(env.UC_DISABLE_RATE_LIMIT),
    logMail: opts.logMail ?? true,
  };
  cfg.requireVerifiedEmail = opts.requireVerifiedEmail ?? (env.UC_REQUIRE_VERIFIED_EMAIL !== undefined ? truthy(env.UC_REQUIRE_VERIFIED_EMAIL) : Boolean(mailKey));
  cfg.googleEnabled = Boolean(cfg.google.clientId && cfg.google.clientSecret);
  return cfg;
}
