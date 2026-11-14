// Platform clipboard backends. Each backend shells out to a native tool so the CLI has no dependencies.
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';

function has(cmd) {
  const probe = process.platform === 'win32' ? 'where' : 'which';
  return spawnSync(probe, [cmd], { stdio: 'ignore' }).status === 0;
}

// `quiet` drops stdout/stderr: selection owners such as xclip fork into the background and would keep
// our pipes open forever, so we must not wait on them.
function run(cmd, args, input, { quiet = false } = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: ['pipe', quiet ? 'ignore' : 'pipe', quiet ? 'ignore' : 'pipe'], windowsHide: true });
    const out = [];
    const err = [];
    p.stdout?.on('data', (d) => out.push(d));
    p.stderr?.on('data', (d) => err.push(d));
    p.on('error', reject);
    p.on('close', (code) => {
      if (code === 0) resolve(Buffer.concat(out).toString('utf8'));
      else reject(new Error(`${cmd} exited ${code}: ${Buffer.concat(err).toString('utf8').trim()}`));
    });
    p.stdin.on('error', () => {});
    p.stdin.end(input ?? '');
  });
}

const PS_UTF8 = '[Console]::OutputEncoding=[Text.Encoding]::UTF8;[Console]::InputEncoding=[Text.Encoding]::UTF8;';

const backends = {
  // Test/headless backend: the "clipboard" is a plain file named by UCLIP_CLIPBOARD_FILE.
  file: {
    read: async () => (existsSync(process.env.UCLIP_CLIPBOARD_FILE) ? readFileSync(process.env.UCLIP_CLIPBOARD_FILE, 'utf8') : ''),
    write: async (text) => writeFileSync(process.env.UCLIP_CLIPBOARD_FILE, text),
  },
  windows: {
    read: async () => (await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `${PS_UTF8}Get-Clipboard -Raw`])).replace(/\r?\n$/, ''),
    write: (text) => run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `${PS_UTF8}Set-Clipboard -Value ([Console]::In.ReadToEnd())`], text),
  },
  macos: {
    read: () => run('pbpaste', []),
    write: (text) => run('pbcopy', [], text),
  },
  termux: {
    read: () => run('termux-clipboard-get', []),
    write: (text) => run('termux-clipboard-set', [], text),
  },
  wayland: {
    read: () => run('wl-paste', ['--no-newline']),
    write: (text) => run('wl-copy', [], text, { quiet: true }),
  },
  xclip: {
    read: () => run('xclip', ['-selection', 'clipboard', '-o']),
    write: (text) => run('xclip', ['-selection', 'clipboard', '-i'], text, { quiet: true }),
  },
  xsel: {
    read: () => run('xsel', ['--clipboard', '--output']),
    write: (text) => run('xsel', ['--clipboard', '--input'], text),
  },
};

export function detectBackend() {
  if (process.env.UCLIP_CLIPBOARD_FILE) return 'file';
  if (process.platform === 'win32') return 'windows';
  if (process.platform === 'darwin') return 'macos';
  if (process.env.TERMUX_VERSION || has('termux-clipboard-get')) return 'termux';
  if (process.env.WAYLAND_DISPLAY && has('wl-paste')) return 'wayland';
  if (process.env.DISPLAY && has('xclip')) return 'xclip';
  if (process.env.DISPLAY && has('xsel')) return 'xsel';
  if (has('wl-paste')) return 'wayland';
  return null;
}

export function getClipboard(name = detectBackend()) {
  if (!name) {
    throw new Error(
      'No clipboard tool found. Install one of: wl-clipboard (Wayland), xclip or xsel (X11), termux-api (Android/Termux).',
    );
  }
  return { name, ...backends[name] };
}
