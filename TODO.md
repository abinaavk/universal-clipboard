# TODO

## Before launch
- [ ] Host it (`docker compose up -d --build`, or `gunicorn app:app`), fill in `.env`, point the HTTPS proxy for `uclip.gaiasentinel.online` at `UC_PORT` (default 7410)
- [ ] Add Resend key + verified sending domain (without it, email verification is off and reset links only print to the server log)
- [ ] Add Google OAuth client ID/secret, redirect URI `https://uclip.gaiasentinel.online/api/v1/auth/google/callback`
- [ ] Review the draft `/privacy` and `/terms` pages and replace the placeholder `@gaiasentinel.online` contact addresses
- [ ] Run `app.py` under real gunicorn (only tried under a stdlib WSGI server so far)

## Test on real hardware (not exercised yet)
- [ ] Windows: PowerShell clipboard backend and `install.ps1`
- [ ] Linux: Wayland (`wl-clipboard`) and X11 (`xclip`/`xsel`) backends
- [ ] Android: Termux daemon, installable PWA, Share target
- [ ] A real Google account and real email delivery

## Possible improvements
- [ ] Python (Flask) version of the server, if the host has no Node.js
- [ ] Image and file support (clipboard items are text only)
- [ ] Use a real database instead of the single JSON file before running for many users
- [ ] Event-driven clipboard watching instead of polling once a second
- [ ] Background sync on Android without Termux
- [ ] Stop a leftover `node server/server.js` when gunicorn is killed with SIGKILL
