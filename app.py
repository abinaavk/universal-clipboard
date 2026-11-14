#!/usr/bin/env python3
"""Start the Universal Clipboard site (Node relay + web app) from Python.

    python3 app.py

Reads ./.env (without overriding variables already set in the environment),
listens on UC_PORT (default 7410) on UC_BIND (default 0.0.0.0) and runs
server/server.js with Node 20+. Python standard library only.
"""
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def load_env(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if value:  # blank template values must not shadow the server's defaults
            os.environ.setdefault(key, value)


def node_major(node: str) -> int:
    out = subprocess.run([node, "--version"], capture_output=True, text=True, check=True).stdout
    return int(out.strip().lstrip("v").split(".")[0])


def main() -> int:
    load_env(ROOT / ".env")

    node = shutil.which("node")
    if not node:
        sys.exit("Node.js 20 or newer is required but `node` was not found on PATH.")
    if node_major(node) < 20:
        sys.exit("Node.js 20 or newer is required.")

    env = os.environ.copy()
    env.setdefault("NODE_ENV", "production")
    env["PORT"] = env.get("PORT") or env.get("UC_PORT") or "7410"
    env["HOST"] = env.get("HOST") or env.get("UC_BIND") or "0.0.0.0"
    env.setdefault("UC_DATA_DIR", str(ROOT / "data"))
    if "UC_PUBLIC_URL" not in env and env.get("UC_DOMAIN"):
        env["UC_PUBLIC_URL"] = f"https://{env['UC_DOMAIN']}"
    # The site is meant to sit behind an HTTPS proxy/tunnel.
    env.setdefault("UC_TRUST_PROXY", "1")

    print(f"Universal Clipboard: http://{env['HOST']}:{env['PORT']}  (public: {env.get('UC_PUBLIC_URL', 'default')})", flush=True)
    proc = subprocess.Popen([node, str(ROOT / "server" / "server.js")], cwd=ROOT, env=env)

    def forward(signum, _frame):
        proc.send_signal(signum)

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, forward)
    return proc.wait()


if __name__ == "__main__":
    sys.exit(main())
