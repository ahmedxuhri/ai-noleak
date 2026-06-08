#!/usr/bin/env sh
# Scripts to build pre-release archives for all platforms locally.
set -eu

platforms="linux/amd64 linux/arm64 linux/arm/v7 darwin/amd64 darwin/arm64"
distdir="dist"

echo "Cleaning dist/ directory..."
rm -rf "$distdir"
mkdir -p "$distdir"

if ! command -v go >/dev/null 2>&1; then
  if [ -x /usr/local/go/bin/go ]; then
    GO=/usr/local/go/bin/go
  else
    echo "build-releases: Go is required. Install Go or set PATH to include go." >&2
    exit 1
  fi
else
  GO=go
fi

for platform in $platforms; do
  goos=$(echo "$platform" | cut -d'/' -f1)
  goarch=$(echo "$platform" | cut -d'/' -f2)
  goarm=""
  if [ "$goarch" = "arm" ]; then
    goarm=$(echo "$platform" | cut -d'/' -f3 | sed 's/v//')
  fi

  suffix="${goos}-${goarch}"
  if [ -n "$goarm" ]; then
    suffix="${suffix}v${goarm}"
  fi

  echo "Building $platform..."
  out="$distdir/ai-noleak-${suffix}"
  mkdir -p "$out"

  # Build binaries
  GOOS="$goos" GOARCH="$goarch" GOARM="$goarm" CGO_ENABLED=0 "$GO" build -o "$out/noleakd" ./cmd/noleakd
  GOOS="$goos" GOARCH="$goarch" GOARM="$goarm" CGO_ENABLED=0 "$GO" build -o "$out/noleak-watch" ./cmd/noleak-watch
  GOOS="$goos" GOARCH="$goarch" GOARM="$goarm" CGO_ENABLED=0 "$GO" build -o "$out/noleak" ./cmd/noleak

  # Copy documentation and files
  cp README.md LICENSE SPEC.md FUTURE_WORK.md "$out/"

  # Create tarball
  tar -C "$distdir" -czf "$distdir/ai-noleak-${suffix}.tar.gz" "ai-noleak-${suffix}"
  rm -rf "$out"
done

# Calculate checksums
cd "$distdir"
sha256sum *.tar.gz > SHA256SUMS.txt
echo ""
echo "Build complete! Archives and checksums in dist/ directory:"
cat SHA256SUMS.txt
