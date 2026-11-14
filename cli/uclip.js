#!/usr/bin/env node
// uclip: Universal Clipboard command-line client and sync daemon.
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir, hostname } from 'node:os';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';
import { ApiError, createApi, createClient } from '../shared/client.js';
import { login as passwordLogin } from '../shared/auth.js';
import { fingerprint, fromB64, generateDeviceKeyPair, importVaultKey, openFromApprover, toB64 } from '../shared/crypto.js';
import { getClipboard } from './clipboard.js';

const DEFAULT_SERVER = process.env.UCLIP_SERVER ?? 'https://uclip.gaiasentinel.online';
const CONFIG_PATH =
  process.env.UCLIP_CONFIG ??
  join(process.platform === 'win32' ? (process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming')) : (process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config')), 'universal-clipboard', 'config.json');

const HELP = `uclip - private synchronised clipboard

Create your account on the website first (${DEFAULT_SERVER}/signup), then:

  uclip login [--server <url>] [--device <name>]
        Sign in. Shows a code to approve in your browser (works for Google accounts too).
  uclip login --email <you@example.com> [--password-stdin]
        Sign in directly with email and password.
  uclip logout           Sign out of this device and wipe its stored key
  uclip daemon           Sync the local clipboard with your other signed-in devices
  uclip copy [text]      Send text (or stdin) to the shared clipboard
  uclip paste            Print the newest shared item
  uclip history [-n 10]  List recent items
  uclip devices [--revoke <id>]   List signed-in devices, or sign one out
  uclip whoami           Show the signed-in account
  uclip clear            Delete all shared items
  uclip status           Show configuration, session state and clipboard backend

The daemon only reads or writes your clipboard while this device has an active session.
`;

function parseArgs(argv) {
  const flags = {};
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      const k = eq === -1 ? a.slice(2) : a.slice(2, eq);
      flags[k] = eq !== -1 ? a.slice(eq + 1) : argv[i + 1] && !argv[i + 1].startsWith('-') ? argv[++i] : true;
    } else if (a === '-n') flags.n = argv[++i];
    else rest.push(a);
  }
  return { flags, rest };
}

function die(msg) {
  console.error(msg);
  process.exit(1);
}

const sha = (s) => createHash('sha256').update(s).digest('hex');
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const platform = () => (process.env.TERMUX_VERSION ? 'android' : { win32: 'windows', darwin: 'macos', linux: 'linux' }[process.platform] ?? 'other');

// ---- config -------------------------------------------------------------------------------------

function readConfig() {
  try {
    return JSON.parse(readFileSync(CONFIG_PATH, 'utf8'));
  } catch {
    return null;
  }
}

function writeConfig(cfg) {
  mkdirSync(dirname(CONFIG_PATH), { recursive: true });
  const tmp = `${CONFIG_PATH}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(cfg, null, 2), { mode: 0o600 });
  renameSync(tmp, CONFIG_PATH);
  try {
    chmodSync(CONFIG_PATH, 0o600);
  } catch {}
}

/** Remove this device's credentials, but only if they are still the ones we were using (a newer login must survive). */
function wipeCredentials(token) {
  const cfg = readConfig();
  if (!cfg || (token && cfg.token !== token)) return;
  const { token: _t, vaultKey: _k, ...rest } = cfg;
  writeConfig(rest);
}

const signedIn = (cfg) => Boolean(cfg?.token && cfg?.vaultKey && cfg?.server);

async function connect() {
  const cfg = readConfig();
  if (!signedIn(cfg)) die('Not signed in. Run: uclip login');
  const key = await importVaultKey(fromB64(cfg.vaultKey));
  return { cfg, client: createClient({ server: cfg.server, token: cfg.token, key, device: cfg.device }) };
}

/** Run an API call; if the server says the session is over, wipe local credentials and say so. */
async function guarded(cfg, fn) {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      wipeCredentials(cfg.token);
      die('This device\'s session has ended (signed out or revoked). Run: uclip login');
    }
    throw e;
  }
}

// ---- terminal input -----------------------------------------------------------------------------

function ask(question, { hidden = false } = {}) {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: process.stdin.isTTY });
    if (hidden && process.stdin.isTTY) {
      rl._writeToOutput = (s) => {
        if (s.includes(question)) rl.output.write(s);
      };
    }
    rl.question(question, (answer) => {
      rl.close();
      if (hidden && process.stdin.isTTY) process.stdout.write('\n');
      resolve(answer);
    });
  });
}

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
}

// ---- commands -----------------------------------------------------------------------------------

const commands = {
  async login({ flags }) {
    const prev = readConfig() ?? {};
    const server = String(typeof flags.server === 'string' ? flags.server : (prev.server ?? DEFAULT_SERVER)).replace(/\/+$/, '');
    const device = typeof flags.device === 'string' ? flags.device : (prev.device ?? hostname());
    const api = createApi({ server });

    if (flags.email) {
      const email = String(flags.email);
      const password = flags['password-stdin'] ? (await readStdin()).replace(/\r?\n$/, '') : await ask('Password: ', { hidden: true });
      const res = await passwordLogin(api, { email, password, device, platform: platform(), client: 'cli' });
      writeConfig({ server, device, email: res.user.email, token: res.token, vaultKey: toB64(res.vaultKey) });
      console.log(`Signed in as ${res.user.email} on "${device}".`);
      if (!res.user.emailVerified) console.log('Note: confirm your email address (check your inbox) before the clipboard will sync.');
      return;
    }

    // Device approval: the browser (where you are signed in) hands this device the vault key, sealed to a
    // key that only this process holds.
    const { privateKey, publicKey } = await generateDeviceKeyPair();
    const start = await api.call('POST', '/api/v1/device/start', { device, platform: platform(), pub: publicKey });
    console.log(`\nTo sign in, open:\n\n  ${server}/device?code=${start.userCode}\n\nand confirm this code: ${start.userCode}\nKey check (must match the one on the page): ${await fingerprint(publicKey)}\n\nWaiting for approval (expires in ${Math.round(start.expiresIn / 60)} min)...`);
    const deadline = Date.now() + start.expiresIn * 1000;
    while (Date.now() < deadline) {
      await sleep(start.interval * 1000);
      try {
        const res = await api.call('POST', '/api/v1/device/token', { deviceCode: start.deviceCode });
        const vaultKey = await openFromApprover(privateKey, res.sealed);
        writeConfig({ server, device, email: res.user.email, token: res.token, vaultKey: toB64(vaultKey) });
        console.log(`Signed in as ${res.user.email} on "${device}".`);
        return;
      } catch (e) {
        if (e instanceof ApiError && e.code === 'authorization_pending') continue;
        throw e;
      }
    }
    die('Timed out waiting for approval. Run uclip login again.');
  },

  async logout() {
    const cfg = readConfig();
    if (!cfg) return console.log('Not signed in.');
    if (cfg.token) {
      try {
        await createApi({ server: cfg.server, token: cfg.token }).call('POST', '/api/v1/auth/logout');
      } catch (e) {
        console.error(`Could not reach the server (${e.message}); wiping local credentials anyway. Revoke this device on the website to be sure.`);
      }
    }
    wipeCredentials();
    console.log('Signed out. A running daemon stops syncing immediately.');
  },

  async daemon() {
    const cb = getClipboard();
    const pollMs = Number(process.env.UCLIP_POLL_MS ?? 1000);
    log(`uclip daemon: clipboard backend "${cb.name}"`);
    log('The clipboard is only touched while this device has an active session.');

    let lastHash = null; // hash of the text we know is on the clipboard: stops echoes and re-sends
    let active = null; // { token, client, stop, online }
    let busy = false;
    let retryAt = 0;
    const ownIds = new Set();

    const deactivate = (why, { wipe = false } = {}) => {
      if (!active) return;
      active.stop();
      if (wipe) wipeCredentials(active.token);
      active = null;
      log(`session inactive (${why}); clipboard sync paused`);
    };

    async function activate(cfg) {
      const key = await importVaultKey(fromB64(cfg.vaultKey));
      const client = createClient({ server: cfg.server, token: cfg.token, key, device: cfg.device });
      const state = { token: cfg.token, client, online: false, stop: () => {} };
      active = state;
      // Validate the session first: the OS clipboard is not even read until the server confirms it.
      let lastSeq;
      try {
        ({ lastSeq } = await client.list(Number.MAX_SAFE_INTEGER));
      } catch (e) {
        active = null;
        if (e instanceof ApiError && e.status === 401) {
          wipeCredentials(cfg.token);
          return log('stored session is no longer valid; run: uclip login');
        }
        if (e instanceof ApiError && e.status === 403) {
          retryAt = Date.now() + 15_000;
          return log('this account cannot sync yet (confirm your email address)');
        }
        throw e;
      }
      // Whatever is on the clipboard right now predates this session: never upload it.
      lastHash = sha(await cb.read().catch(() => ''));
      log(`session active for ${cfg.email ?? 'this account'} as "${cfg.device}" on ${cfg.server}`);
      state.stop = client.subscribe({
        since: lastSeq,
        onStatus: (s) => {
          if (active !== state) return;
          if (s === 'ended') return deactivate('signed out, revoked or expired', { wipe: true });
          if (s === 'forbidden') return deactivate('account not allowed to sync (confirm your email)');
          state.online = s === 'online';
          log(`connection: ${s}`);
        },
        onItem: async (item) => {
          if (active !== state || !state.online) return;
          if (item.kind !== 'text' || ownIds.has(item.id)) return;
          const h = sha(item.text);
          if (h === lastHash) return;
          lastHash = h;
          try {
            await cb.write(item.text);
            log(`<- ${item.device} (${item.text.length} chars)`);
          } catch (e) {
            log('clipboard write failed:', e.message);
          }
        },
      });
    }

    async function tick() {
      if (busy || Date.now() < retryAt) return;
      busy = true;
      try {
        const cfg = readConfig();
        if (!signedIn(cfg)) {
          deactivate('signed out');
          return;
        }
        if (active && active.token !== cfg.token) deactivate('credentials changed');
        if (!active) await activate(cfg);
        // Only a session the server has just confirmed is allowed to capture the clipboard.
        if (!active?.online) return;
        const text = await cb.read();
        const h = sha(text);
        if (text && h !== lastHash) {
          lastHash = h;
          try {
            const sent = await active.client.pushText(text);
            if (sent) ownIds.add(sent.id);
            log(`-> sent (${text.length} chars)`);
          } catch (e) {
            if (e instanceof ApiError && e.status === 401) deactivate('session ended', { wipe: true });
            else {
              lastHash = null; // retry on the next tick
              throw e;
            }
          }
        }
      } catch (e) {
        log('error:', e.message);
        retryAt = Date.now() + 3000;
      } finally {
        busy = false;
      }
    }

    if (!signedIn(readConfig())) log('not signed in: waiting. Run `uclip login` in another terminal; the daemon picks it up automatically.');
    const timer = setInterval(tick, pollMs);
    tick();
    for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => (clearInterval(timer), active?.stop(), process.exit(0)));
  },

  async copy({ rest }) {
    const { cfg, client } = await connect();
    const text = rest.length ? rest.join(' ') : await readStdin();
    if (!text) die('Nothing to copy.');
    await guarded(cfg, () => client.pushText(text));
    console.log(`Sent ${text.length} chars.`);
  },

  async paste() {
    const { cfg, client } = await connect();
    const { items } = await guarded(cfg, () => client.list());
    const last = items.filter((i) => i.kind === 'text').at(-1);
    if (!last) die('Shared clipboard is empty.');
    process.stdout.write(last.text);
  },

  async history({ flags }) {
    const { cfg, client } = await connect();
    const { items } = await guarded(cfg, () => client.list());
    for (const i of items.slice(-(Number(flags.n) || 10)).reverse()) {
      const preview = i.text.replace(/\s+/g, ' ').slice(0, 70);
      console.log(`${new Date(i.ts).toLocaleString()}  ${String(i.device).padEnd(14)}  ${preview}`);
    }
  },

  async devices({ flags }) {
    const { cfg, client } = await connect();
    if (typeof flags.revoke === 'string') {
      await guarded(cfg, () => client.revokeSession(flags.revoke));
      return console.log('Device signed out.');
    }
    const { sessions } = await guarded(cfg, () => client.sessions());
    for (const s of sessions) {
      console.log(`${s.id}  ${s.online ? 'online ' : 'offline'}  ${s.platform.padEnd(8)} ${s.device}${s.current ? '  (this device)' : ''}`);
    }
  },

  async whoami() {
    const { cfg, client } = await connect();
    const { user } = await guarded(cfg, () => client.account());
    console.log(`${user.email}${user.emailVerified ? '' : ' (email not confirmed)'}`);
  },

  async clear() {
    const { cfg, client } = await connect();
    await guarded(cfg, () => client.clear());
    console.log('Cleared.');
  },

  async status() {
    const cfg = readConfig();
    let backend = 'none found';
    try {
      backend = getClipboard().name;
    } catch {}
    let session = 'signed out';
    if (signedIn(cfg)) {
      try {
        const { user } = await createApi({ server: cfg.server, token: cfg.token }).call('GET', '/api/v1/account');
        session = `active (${user.email})`;
      } catch (e) {
        session = e instanceof ApiError && e.status === 401 ? 'ended: run uclip login' : `unknown (${e.message})`;
      }
    }
    console.log(`config:    ${CONFIG_PATH}${existsSync(CONFIG_PATH) ? '' : ' (missing)'}\nserver:    ${cfg?.server ?? DEFAULT_SERVER}\ndevice:    ${cfg?.device ?? hostname()}\nsession:   ${session}\nclipboard: ${backend}`);
  },
};

const [cmd, ...argv] = process.argv.slice(2);
if (!cmd || cmd === 'help' || cmd === '--help' || !commands[cmd]) {
  console.log(HELP);
  process.exit(cmd && cmd !== 'help' && cmd !== '--help' ? 1 : 0);
}
commands[cmd](parseArgs(argv)).catch((e) => die(`uclip: ${e.message}`));
