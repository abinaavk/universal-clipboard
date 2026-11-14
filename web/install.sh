#!/bin/sh
# Universal Clipboard installer for Linux, macOS and Termux (Android).
# Downloads the small `uclip` command-line app from {{ORIGIN}} into your home directory.
# Read it first if you like: curl -fsSL {{ORIGIN}}/install.sh
set -eu

ORIGIN="{{ORIGIN}}"
DEST="${UCLIP_HOME:-$HOME/.local/share/uclip}"
if [ -n "${TERMUX_VERSION:-}" ] && [ -n "${PREFIX:-}" ]; then BIN="${UCLIP_BIN:-$PREFIX/bin}"; else BIN="${UCLIP_BIN:-$HOME/.local/bin}"; fi

say() { printf '%s\n' "$*"; }
die() { printf 'uclip install: %s\n' "$*" >&2; exit 1; }

command -v node >/dev/null 2>&1 || die "Node.js 20 or newer is required (https://nodejs.org). On Termux: pkg install nodejs"
node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 20 ? 0 : 1)' || die "Node.js 20 or newer is required (found $(node -v))"

if command -v curl >/dev/null 2>&1; then fetch() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then fetch() { wget -qO- "$1"; }
else die "curl or wget is required"; fi

mkdir -p "$DEST/cli" "$DEST/shared" "$BIN"
for f in cli/uclip.js cli/clipboard.js shared/client.js shared/crypto.js shared/auth.js; do
  fetch "$ORIGIN/dl/$f" > "$DEST/$f.tmp" || die "could not download $f"
  mv "$DEST/$f.tmp" "$DEST/$f"
done
printf '{"type":"module"}\n' > "$DEST/package.json"

cat > "$BIN/uclip" <<EOF
#!/bin/sh
UCLIP_SERVER="\${UCLIP_SERVER:-$ORIGIN}"
export UCLIP_SERVER
exec node "$DEST/cli/uclip.js" "\$@"
EOF
chmod +x "$BIN/uclip"

say "Installed uclip to $BIN/uclip"
case ":$PATH:" in *":$BIN:"*) ;; *) say "Add $BIN to your PATH to run 'uclip' from anywhere." ;; esac
if [ "$(uname -s)" = "Linux" ] && [ -z "${TERMUX_VERSION:-}" ] && ! command -v wl-paste >/dev/null 2>&1 && ! command -v xclip >/dev/null 2>&1 && ! command -v xsel >/dev/null 2>&1; then
  say "Note: install a clipboard tool: wl-clipboard (Wayland) or xclip (X11)."
fi
say ""
say "Next:  uclip login     (approve the code in your browser)"
say "       uclip daemon    (keeps your clipboard in sync)"
