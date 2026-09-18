#!/usr/bin/env bash
# Lays a binary out as a release store the action can download from, so the
# download + checksum path is tested before (and independently of) any real
# release:  <root>/download/<version>/{discipline-<triple>.tar.gz,SHA256SUMS}
#
#   fake-release.sh <binary> <root> <version> [tamper]
# `tamper` corrupts the archive after the checksum is written.
set -euo pipefail

bin="${1:?binary}"
root="${2:?release root}"
version="${3:?version}"
tamper="${4:-}"

case "$(uname -m)" in
  x86_64|amd64) arch="x86_64" ;;
  aarch64|arm64) arch="aarch64" ;;
  *) echo "unsupported architecture" >&2; exit 2 ;;
esac
case "$(uname -s)" in
  Linux) triple="${arch}-unknown-linux-musl" ;;
  Darwin) triple="${arch}-apple-darwin" ;;
  *) echo "unsupported OS" >&2; exit 2 ;;
esac

dest="${root}/download/${version}"
rm -rf "${dest}"
mkdir -p "${dest}"
stage="$(mktemp -d)"
cp "${bin}" "${stage}/discipline"
tar -czf "${dest}/discipline-${triple}.tar.gz" -C "${stage}" .
if command -v sha256sum >/dev/null 2>&1; then
  (cd "${dest}" && sha256sum discipline-*.tar.gz > SHA256SUMS)
else
  (cd "${dest}" && shasum -a 256 discipline-*.tar.gz > SHA256SUMS)
fi
if [ "${tamper}" = "tamper" ]; then
  printf 'x' >> "${dest}/discipline-${triple}.tar.gz"
fi
echo "fake release ${version} at ${dest}"
