#!/usr/bin/env sh
# ai-noleak installer script.
#
# Usage:
#   sh install.sh           # Run from source directory to compile and install
#   curl -fsSL https://raw.githubusercontent.com/ahmedxuhri/ai-noleak/main/scripts/install.sh | sh
#                           # Download prebuilt binary and install
#
set -eu

REPO="ahmedxuhri/ai-noleak"
prefix="${PREFIX:-}"
if [ -z "$prefix" ]; then
  if [ "$(id -u)" -eq 0 ]; then
    prefix="/usr/local"
  else
    prefix="$HOME/.local"
  fi
fi

bindir="$prefix/bin"

# Detect if we are inside a source checkout
is_src_checkout=0
if [ -d "./cmd/noleak" ] && [ -d "./internal" ] && [ -f "go.mod" ]; then
  is_src_checkout=1
fi

install_from_src() {
  echo ">>> Installing from source..."
  if ! command -v go >/dev/null 2>&1; then
    if [ -x /usr/local/go/bin/go ]; then
      GO=/usr/local/go/bin/go
    else
      echo "install: Go is required to compile from source. Install Go or set PATH." >&2
      exit 1
    fi
  else
    GO=go
  fi

  mkdir -p bin "$bindir"
  for cmd in noleakd noleak-watch noleak; do
    echo "Building $cmd..."
    "$GO" build -o "bin/$cmd" "./cmd/$cmd"
    echo "Installing $bindir/$cmd..."
    install -m 0755 "bin/$cmd" "$bindir/$cmd"
  done
}

install_from_release() {
  echo ">>> Installing prebuilt binaries from GitHub Releases..."
  
  # Detect OS
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$OS" in
    linux)  OS="linux" ;;
    darwin) OS="darwin" ;;
    *)
      echo "install: Unsupported operating system: $OS. Attempting to build from source instead..." >&2
      if command -v go >/dev/null 2>&1 || [ -x /usr/local/go/bin/go ]; then
        install_from_src
        return
      else
        exit 1
      fi
      ;;
  esac

  # Detect Architecture
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    armv7l) ARCH="armv7" ;;
    *)
      echo "install: Unsupported architecture: $ARCH. Attempting to build from source instead..." >&2
      if command -v go >/dev/null 2>&1 || [ -x /usr/local/go/bin/go ]; then
        install_from_src
        return
      else
        exit 1
      fi
      ;;
  esac

  # Get latest release tag
  echo "Detecting latest release tag..."
  TAG=$(curl -sfI "https://github.com/$REPO/releases/latest" | grep -i "^location:" | grep -oE "tag/v[0-9.]+" | cut -d'/' -f2)
  if [ -z "$TAG" ]; then
    # Fallback to fetching it via github api or default
    TAG=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
  fi
  if [ -z "$TAG" ]; then
    echo "install: Could not detect latest tag. Attempting to compile from source..." >&2
    install_from_src
    return
  fi

  TARBALL="ai-noleak-${OS}-${ARCH}.tar.gz"
  URL="https://github.com/$REPO/releases/download/$TAG/$TARBALL"

  echo "Downloading $URL..."
  tmpdir=$(mktemp -d)
  defer_cleanup() {
    rm -rf "$tmpdir"
  }
  trap defer_cleanup EXIT

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$tmpdir/$TARBALL" "$URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$tmpdir/$TARBALL" "$URL"
  else
    echo "install: curl or wget is required to download prebuilt binaries." >&2
    exit 1
  fi

  echo "Extracting archives..."
  tar -C "$tmpdir" -xzf "$tmpdir/$TARBALL"

  mkdir -p "$bindir"
  subdir="ai-noleak-${OS}-${ARCH}"
  for cmd in noleakd noleak-watch noleak; do
    echo "Installing $bindir/$cmd..."
    install -m 0755 "$tmpdir/$subdir/$cmd" "$bindir/$cmd"
  done
}

if [ "$is_src_checkout" -eq 1 ]; then
  install_from_src
else
  install_from_release
fi

# Configuration Setup
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
  echo "Created default config in $HOME/.noleak/config.yaml"
fi

echo "Successfully installed ai-noleak to $bindir!"
echo "Next steps:"
echo "  1. Edit $HOME/.noleak/config.yaml and set your 'proxy_upstream'"
echo "  2. Run 'noleak start --ephemeral' to start all services"
echo "  3. Configure your AI CLI base URL to http://127.0.0.1:9999/v1"
echo "  4. Verify the setup with 'noleak doctor'"
