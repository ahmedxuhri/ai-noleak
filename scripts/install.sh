#!/usr/bin/env sh
set -eu

prefix="${PREFIX:-}"
if [ -z "$prefix" ]; then
  if [ "$(id -u)" -eq 0 ]; then
    prefix="/usr/local"
  else
    prefix="$HOME/.local"
  fi
fi

bindir="$prefix/bin"
srcdir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

if ! command -v go >/dev/null 2>&1; then
  if [ -x /usr/local/go/bin/go ]; then
    GO=/usr/local/go/bin/go
  else
    echo "install: Go is required. Install Go or set PATH to include go." >&2
    exit 1
  fi
else
  GO=go
fi

cd "$srcdir"
mkdir -p bin "$bindir"

for cmd in noleakd noleak-watch noleak; do
  echo "build $cmd"
  "$GO" build -o "bin/$cmd" "./cmd/$cmd"
  echo "install $bindir/$cmd"
  install -m 0755 "bin/$cmd" "$bindir/$cmd"
done

mkdir -p "$HOME/.noleak"
chmod 700 "$HOME/.noleak"

if [ ! -f "$HOME/.noleak/config.yaml" ]; then
  cat > "$HOME/.noleak/config.yaml" <<'EOF'
proxy_listen: 127.0.0.1:9999
proxy_upstream: ""
proxy_preserve_headers:
  - Authorization
  - X-Api-Key
  - Anthropic-Version
  - Anthropic-Beta
  - User-Agent
  - Accept
  - Content-Type
proxy_passthrough_tokens: []
EOF
  chmod 600 "$HOME/.noleak/config.yaml"
  echo "created $HOME/.noleak/config.yaml"
fi

echo "installed ai-noleak to $bindir"
echo "next: edit $HOME/.noleak/config.yaml, start noleakd, then run noleak doctor"
