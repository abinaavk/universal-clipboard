#!/usr/bin/env node
// uclip: Universal Clipboard command-line client and sync daemon.
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir, hostname } from 'node:os';
import { dirname, join } from 'node:path';
import { createClient } from '../shared/client.js';
import { deriveKeys, generatePassphrase } from '../shared/crypto.js';
import { getClipboard } from './clipboard.js';

const CONFIG_PATH =
  process.env.UCLIP_CONFIG ??
  join(process.platform === 'win32' ? (process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming')) : (process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config')), 'universal-clipboard', 'config.json');

const HELP = `uclip - private synchronised clipboard

Usage:
  uclip init --server <url> [--passphrase <p>] [--device <name>]
        Create/join a vault. Without --passphrase a new one is generated.
  uclip daemon           Watch the local clipboard and sync it with your other devices
  uclip copy [text]      Send text (or stdin) to the shared clipboard
  uclip paste            Print the newest shared item
  uclip history [-n 10]  List recent items
  uclip pair             Print a link that signs a browser/phone into the same vault
  uclip clear            Delete all shared items
  uclip status           Show configuration and clipboard backend
`;

function parseArgs(argv) {
  const flags = {};
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const [k, v] = a.slice(2).split('=');
      flags[k] = v ?? (argv[i + 1] && !argv[i + 1].startsWith('-') ? argv[++i] : true);
    } else if (a === '-n') flags.n = argv[++i];
    else rest.push(a);
  }
  return { flags, rest };
}

function loadConfig() {
  if (!existsSync(CONFIG_PATH)) die(`Not configured. Run: uclip init --server <url>\n(config expected at ${CONFIG_PATH})`);
  return JSON.parse(readFileSync(CONFIG_PATH, 'utf8'));
}

function die(msg) {
  console.error(msg);
  process.exit(1);
}

async function connect() {
  const cfg = loadConfig();
  const { token, key } = await deriveKeys(cfg.passphrase);
  return { cfg, client: createClient({ server: cfg.server, token, key, device: cfg.device, inviteCode: cfg.inviteCode }) };
}

const sha = (s) => createHash('sha256').update(s).digest('hex');
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
}

const commands = {
  async init({ flags }) {
    if (!flags.server || flags.server === true) die('--server <url> is required');
    const passphrase = typeof flags.passphrase === 'string' ? flags.passphrase : generatePassphrase();
    const cfg = {
      server: flags.server,
      passphrase,
      device: typeof flags.device === 'string' ? flags.device : hostname(),
      ...(typeof flags.invite === 'string' ? { inviteCode: flags.invite } : {}),
    };
    mkdirSync(dirname(CONFIG_PATH), { recursive: true });
    writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2), { mode: 0o600 });
    try {
      chmodSync(CONFIG_PATH, 0o600);
    } catch {}
    console.log(`Saved ${CONFIG_PATH}`);
    if (typeof flags.passphrase !== 'string') {
      console.log(`\nNew vault passphrase (keep it secret; use it on your other devices):\n\n  ${passphrase}\n`);
    }
    const { client } = await connect();
    await client.list();
    console.log('Connected to server.');
  },

  async daemon() {
    const { cfg, client } = await connect();
    const cb = getClipboard();
    log(`uclip daemon: device "${cfg.device}", clipboard backend "${cb.name}", server ${cfg.server}`);

    // Hash of the last text we know is on the clipboard, so we neither echo remote writes back nor re-send.
    let lastHash = sha(await cb.read().catch(() => ''));
    const { lastSeq } = await client.list(Number.MAX_SAFE_INTEGER);
    let busy = false;

    const stop = client.subscribe({
      since: lastSeq,
      onStatus: (s) => log(`connection: ${s}`),
      onItem: async (item) => {
        if (item.kind !== 'text' || item.device === cfg.device) return;
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

    const poll = async () => {
      if (busy) return;
      busy = true;
      try {
        const text = await cb.read();
        const h = sha(text);
        if (text && h !== lastHash) {
          lastHash = h;
          await client.pushText(text);
          log(`-> sent (${text.length} chars)`);
        }
      } catch (e) {
        log('poll error:', e.message);
      } finally {
        busy = false;
      }
    };
    const timer = setInterval(poll, Number(process.env.UCLIP_POLL_MS ?? 1000));
    for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => (clearInterval(timer), stop(), process.exit(0)));
  },

  async copy({ rest }) {
    const { client } = await connect();
    const text = rest.length ? rest.join(' ') : await readStdin();
    if (!text) die('Nothing to copy.');
    await client.pushText(text);
    console.log(`Sent ${text.length} chars.`);
  },

  async paste() {
    const { client } = await connect();
    const { items } = await client.list();
    const last = items.filter((i) => i.kind === 'text').at(-1);
    if (!last) die('Shared clipboard is empty.');
    process.stdout.write(last.text);
  },

  async history({ flags }) {
    const { client } = await connect();
    const { items } = await client.list();
    for (const i of items.slice(-(Number(flags.n) || 10)).reverse()) {
      const preview = i.text.replace(/\s+/g, ' ').slice(0, 70);
      console.log(`${new Date(i.ts).toLocaleString()}  ${String(i.device).padEnd(14)}  ${preview}`);
    }
  },

  async pair() {
    const cfg = loadConfig();
    // The fragment is never sent to the server by the browser.
    console.log(`${cfg.server.replace(/\/+$/, '')}/#pp=${encodeURIComponent(cfg.passphrase)}`);
    console.error('Open this link on the other device. Treat it like a password.');
  },

  async clear() {
    const { client } = await connect();
    await client.clear();
    console.log('Cleared.');
  },

  async status() {
    const cfg = loadConfig();
    let backend = 'none found';
    try {
      backend = getClipboard().name;
    } catch {}
    console.log(`config:    ${CONFIG_PATH}\nserver:    ${cfg.server}\ndevice:    ${cfg.device}\nclipboard: ${backend}`);
  },
};

const [cmd, ...argv] = process.argv.slice(2);
if (!cmd || cmd === 'help' || cmd === '--help' || !commands[cmd]) {
  console.log(HELP);
  process.exit(cmd && cmd !== 'help' && cmd !== '--help' ? 1 : 0);
}
commands[cmd](parseArgs(argv)).catch((e) => die(`uclip: ${e.message}`));
