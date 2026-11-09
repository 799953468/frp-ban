#!/usr/bin/env bash
set -euo pipefail

# Keep both CI providers on the same packager version. Verify upstream checksums.
version=2.48.0
case "$(uname -m)" in
  x86_64) arch=x86_64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo 'Unsupported nFPM host architecture' >&2; exit 1 ;;
esac
asset="nfpm_${version}_Linux_${arch}.tar.gz"
base="https://github.com/goreleaser/nfpm/releases/download/v${version}"
mkdir -p .tools
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl --fail --silent --show-error --location --retry 3 "$base/$asset" --output "$work/$asset"
curl --fail --silent --show-error --location --retry 3 "$base/checksums.txt" --output "$work/checksums.txt"
(cd "$work"; awk -v asset="$asset" '$2 == asset {print; found=1} END {if (!found) exit 1}' checksums.txt | sha256sum --check --strict)
tar -xzf "$work/$asset" -C .tools nfpm
.tools/nfpm --version
