#!/usr/bin/env python3
"""Start the Universal Clipboard site (Node relay + web app) from Python.

    python3 app.py                                  # run directly
    gunicorn --workers 1 --threads 64 app:app       # or as a WSGI app

Reads ./.env (without overriding variables already set in the environment) and
runs server/server.js with Node 20+. Python standard library only; the single
requirements.txt entry (gunicorn) is just the production WSGI server.

* `python3 app.py` starts Node on UC_PORT / UC_BIND (default 7410 / 0.0.0.0).
* `app` / `application` is a WSGI callable. It starts Node on 127.0.0.1:UC_NODE_PORT
  (default 7411) on the first request and reverse-proxies everything to it,
  including the live event stream. Use ONE worker with several threads: the
  server keeps its data in a single file and holds the live connections.
"""
import atexit
import http.client
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}


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


def find_node() -> str:
    node = shutil.which("node")
    if not node:
        raise RuntimeError("Node.js 20 or newer is required but `node` was not found on PATH.")
    if node_major(node) < 20:
        raise RuntimeError("Node.js 20 or newer is required.")
    return node


def node_env(port: str, host: str) -> dict:
    env = os.environ.copy()
    env.setdefault("NODE_ENV", "production")
    env["PORT"] = port
    env["HOST"] = host
    env.setdefault("UC_DATA_DIR", str(ROOT / "data"))
    if "UC_PUBLIC_URL" not in env and env.get("UC_DOMAIN"):
        env["UC_PUBLIC_URL"] = f"https://{env['UC_DOMAIN']}"
    # The site is meant to sit behind an HTTPS proxy/tunnel.
    env.setdefault("UC_TRUST_PROXY", "1")
    return env


def spawn_node(port: str, host: str) -> subprocess.Popen:
    return subprocess.Popen([find_node(), str(ROOT / "server" / "server.js")], cwd=ROOT, env=node_env(port, host))


# --------------------------------------------------------------------------- script mode

def main() -> int:
    load_env(ROOT / ".env")
    try:
        find_node()
    except RuntimeError as exc:
        sys.exit(str(exc))

    port = os.environ.get("PORT") or os.environ.get("UC_PORT") or "7410"
    host = os.environ.get("HOST") or os.environ.get("UC_BIND") or "0.0.0.0"
    env = node_env(port, host)
    print(f"Universal Clipboard: http://{host}:{port}  (public: {env.get('UC_PUBLIC_URL', 'default')})", flush=True)
    proc = spawn_node(port, host)

    def forward(signum, _frame):
        proc.send_signal(signum)

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, forward)
    return proc.wait()


# --------------------------------------------------------------------------- WSGI mode

load_env(ROOT / ".env")
NODE_HOST = "127.0.0.1"
NODE_PORT = int(os.environ.get("UC_NODE_PORT") or 7411)
_node: subprocess.Popen | None = None
_node_lock = threading.Lock()


def _node_ready() -> bool:
    try:
        conn = http.client.HTTPConnection(NODE_HOST, NODE_PORT, timeout=1)
        conn.request("GET", "/healthz")
        return conn.getresponse().status == 200
    except OSError:
        return False


def _stop_node() -> None:
    if _node and _node.poll() is None:
        _node.terminate()
        try:
            _node.wait(5)
        except subprocess.TimeoutExpired:
            _node.kill()


def ensure_node() -> None:
    """Start the Node server once (or reuse one that is already listening)."""
    global _node
    with _node_lock:
        if _node is not None and _node.poll() is None:
            return
        if _node is None and _node_ready():
            return  # started by another process
        _node = spawn_node(str(NODE_PORT), NODE_HOST)
        atexit.register(_stop_node)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if _node.poll() is not None:
                raise RuntimeError(f"Node server exited with code {_node.returncode} on start")
            if _node_ready():
                return
            time.sleep(0.1)
        raise RuntimeError("Node server did not become ready in 15 seconds")


def _stream(conn: http.client.HTTPConnection, resp: http.client.HTTPResponse):
    try:
        while True:
            chunk = resp.read1(16384)  # returns as soon as data arrives, so live events flow
            if not chunk:
                return
            yield chunk
    finally:
        conn.close()


def app(environ, start_response):
    """WSGI reverse proxy to the Node server."""
    try:
        ensure_node()
    except RuntimeError as exc:
        print(f"Universal Clipboard: {exc}", file=sys.stderr, flush=True)
        start_response("503 Service Unavailable", [("Content-Type", "text/plain; charset=utf-8"), ("Retry-After", "5")])
        return [b"Service starting, retry shortly.\n"]

    headers = {}
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            headers[key[5:].replace("_", "-").title()] = value
    for key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
        if environ.get(key):
            headers[key.replace("_", "-").title()] = environ[key]
    for name in list(headers):
        if name.lower() in HOP_BY_HOP:
            del headers[name]
    # Node trusts the last X-Forwarded-For entry (set by the front proxy); keep it, else use the peer.
    if not headers.get("X-Forwarded-For"):
        headers["X-Forwarded-For"] = environ.get("REMOTE_ADDR", "")
    headers.setdefault("X-Forwarded-Proto", environ.get("wsgi.url_scheme", "http"))

    length = int(environ.get("CONTENT_LENGTH") or 0)
    body = environ["wsgi.input"].read(length) if length > 0 else None
    target = environ.get("RAW_URI") or (environ.get("PATH_INFO", "/") + (f"?{environ['QUERY_STRING']}" if environ.get("QUERY_STRING") else ""))

    conn = http.client.HTTPConnection(NODE_HOST, NODE_PORT, timeout=10)
    try:
        conn.request(environ["REQUEST_METHOD"], target, body=body, headers=headers)
        conn.sock.settimeout(None)  # the event stream stays open indefinitely
        resp = conn.getresponse()
    except OSError:
        conn.close()
        start_response("502 Bad Gateway", [("Content-Type", "text/plain; charset=utf-8")])
        return [b"Upstream unavailable.\n"]

    out = [(k, v) for k, v in resp.getheaders() if k.lower() not in HOP_BY_HOP]
    start_response(f"{resp.status} {resp.reason}", out)
    if environ["REQUEST_METHOD"] == "HEAD":
        conn.close()
        return []
    return _stream(conn, resp)


application = app  # for hosts that look for `application` (Passenger/cPanel)


if __name__ == "__main__":
    sys.exit(main())
