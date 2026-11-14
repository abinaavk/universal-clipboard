# Universal Clipboard (uclip)

Copy on one device, paste on another. A private, **end-to-end encrypted** clipboard that syncs live across Windows, Linux, macOS, Android and any browser, with real accounts (email + password or Google).

Live site: <https://uclip.gaiasentinel.online>

![How it works](docs/how-it-works.png)

## Using it

1. **Create an account** on the website: `/signup` (email + password, or Continue with Google).
2. **Sign in on each device**
   - *Browser / Android web app:* open the site and sign in. Menu → Install app on Android.
   - *Windows, Linux, macOS, Termux:* install the app and run `uclip login`. It prints a code; open the link, confirm the code and your password in the browser. (`uclip login --email you@example.com` signs in directly with email and password.)
3. **Copy as usual.** Run `uclip daemon` (or keep the web tab open). Anything copied on a signed-in device appears on the others within about a second.

```bash
# Linux / macOS / Termux (needs Node.js 20+; on Linux also wl-clipboard or xclip)
curl -fsSL https://uclip.gaiasentinel.online/install.sh | sh
# Windows (PowerShell, needs Node.js 20+)
irm https://uclip.gaiasentinel.online/install.ps1 | iex

uclip login
uclip daemon
```

Other commands: `uclip copy "text"`, `uclip paste`, `uclip history -n 10`, `uclip devices [--revoke <id>]`, `uclip whoami`, `uclip clear`, `uclip logout`, `uclip status`.

Run the daemon at login: on Linux put `ExecStart=%h/.local/bin/uclip daemon` in a systemd user unit (`systemctl --user enable --now uclip`); on Windows create a Task Scheduler task "At log on" running `uclip.cmd daemon`. The daemon waits quietly while signed out and starts syncing by itself after `uclip login`.

### Only active sessions touch the clipboard

- A device syncs only while its session is valid *and* currently confirmed by the server. No session, or offline from the server, means nothing is uploaded and nothing is written locally.
- Sign out (`uclip logout`, or **Sign out** next to a device on the website), password change, password reset, account deletion or 30 days of disuse all end sessions. The server cuts the live connection immediately; the daemon stops, **wipes its stored token and vault key**, and resumes automatically after the next `uclip login`.
- Whatever was on the clipboard before a session starts is never uploaded.
- The web app only auto-copies and captures the clipboard while signed in.

## Security model

- Each account has a random 256-bit **vault key** that encrypts items (AES-256-GCM) on the device. The server stores it only **wrapped**.
- *Password accounts:* PBKDF2-SHA-256 (310k) of the password, salted with the email, yields 512 bits. One half is the `authKey` (the server stores only a salted scrypt hash of it); the other half is the key that wraps the vault key. The password never leaves the device.
- *Google accounts:* no password to derive from, so the user creates a **clipboard passphrase** that wraps the vault key the same way.
- *New CLI devices* get the vault key sealed (ECDH P-256 + HKDF + AES-GCM) to a one-time key held by that process; the approving browser unseals it with your password and the server only relays the blob.
- Sessions: random 256-bit tokens, only SHA-256 stored. Browsers use an `HttpOnly; SameSite=Strict; Secure` cookie plus CSRF header and origin check; devices use bearer tokens.
- Password reset **cannot** recover old clipboard items (they were encrypted under the lost key), so reset deletes them.
- Website: strict CSP (no inline script/style, no third-party origins), HSTS, no framing, no referrer, permissions policy, rate limits per address and per account, generic responses for password-reset requests.
- Limits: text only; items kept 7 days (max 100); a weak password is guessable offline if the server data leaks; a compromised device can read its own clipboard. See `/security`.

## Running the server

```bash
npm start                 # http://127.0.0.1:8787, no dependencies, Node 20+
npm test
```

Production (Docker). The relay is published on host port `UC_PORT` (default `7410`, pick any free port in 7000-8000):

```bash
# 1. fill in .env (committed with empty values): UC_PORT, UC_RESEND_API_KEY, UC_GOOGLE_CLIENT_ID/SECRET, ...
docker compose up -d --build    # http://<host>:7410
# 2. point your HTTPS reverse proxy / tunnel for uclip.gaiasentinel.online at that port
#    (set UC_BIND=127.0.0.1 in .env if the proxy is on the same machine)
```

Without Docker (or on a host that runs a Python start file): `python3 app.py`. It reads `.env`, listens on `UC_PORT`/`UC_BIND` and starts the Node server, so Node.js 20+ must be installed.

HTTPS is required for the web app, Google sign-in and the installers. To let this stack serve HTTPS itself (ports 80/443, automatic certificates) use `docker compose --profile https up -d --build`.

Do not push real keys back to git: `.env` is tracked only as an empty template.

What you need to supply:

| Need | Why | Where |
|---|---|---|
| A host with ports 80/443 and DNS `A/AAAA` for `uclip.gaiasentinel.online` | Hosting and TLS | your DNS / VPS |
| `UC_RESEND_API_KEY` (+ verified sending domain) | Confirmation and reset emails. Without it links are printed to the server log and email verification is off | resend.com |
| `UC_GOOGLE_CLIENT_ID` / `UC_GOOGLE_CLIENT_SECRET` | Google sign-in. Redirect URI: `https://uclip.gaiasentinel.online/api/v1/auth/google/callback` | Google Cloud Console → Credentials |

Configuration (environment): `UC_PUBLIC_URL`, `UC_DATA_DIR`, `UC_SIGNUPS=open|closed`, `UC_INVITE_CODE`, `UC_MAX_USERS`, `UC_REQUIRE_VERIFIED_EMAIL`, `UC_SESSION_TTL_DAYS`, `UC_TTL_HOURS`, `UC_MAX_ITEMS`, `UC_TRUST_PROXY=1` (behind a reverse proxy; the Docker image sets it), `UC_MAIL_FROM`. Back up the `/data` volume (`db.json`).

The store is a single JSON file, which suits a personal or small deployment. Use a real database before running it for many thousands of users.

## API

OpenAPI 3.1 at `/api/v1/openapi.json`, rendered at `/docs`. Website extras: `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`, Open Graph image, JSON-LD, installable PWA with Android share target.

## Layout

```
app.py    Python launcher: loads .env and starts server/server.js
server/   relay + website server (http, auth, google, mail, rate limit, openapi)
shared/   crypto, API client and account flows used by both browser and CLI
cli/      uclip command + daemon, clipboard backends (Windows, Wayland, X11, macOS, Termux)
web/      landing, docs, legal pages and the app (static, no build step)
deploy/   Caddyfile and env example;  Dockerfile and docker-compose.yml at the root
test/     node:test suites (crypto, server/accounts/google/website, daemon e2e)
```

## Status

Automated tests cover accounts, sessions, Google flow (against a mock Google), device approval, CSRF, rate limiting, the website/SEO files, the installer, and two real `uclip daemon` processes including the session-only behaviour. The web app was driven in headless Chromium (sign-up, live sync between two browsers, revoke). **Not yet exercised on real hardware:** the Windows PowerShell backend and `install.ps1`, Wayland/X11/Termux backends, the Android PWA, and a real Google/Resend account.
