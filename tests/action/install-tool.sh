#!/usr/bin/env bash
# Installs a pinned, checksum-verified CI tool into ~/.local/bin.
#   install-tool.sh actionlint|act
# Linux x86_64 only: this is for the hosted CI runners, not developer machines.
set -euo pipefail

case "${1:?tool name}" in
  actionlint)
    url="https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz"
    sha="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
    ;;
  act)
    url="https://github.com/nektos/act/releases/download/v0.2.89/act_Linux_x86_64.tar.gz"
    sha="0191d6f1f3b716b5c55820032605d05fc3c1cdbf581ebeff655019e5dd1524c0"
    ;;
  *)
    echo "unknown tool: $1" >&2
    exit 2
    ;;
esac

tmp="$(mktemp -d)"
curl --fail --silent --show-error --location --retry 3 --output "${tmp}/tool.tar.gz" "${url}"
echo "${sha}  ${tmp}/tool.tar.gz" | sha256sum --check --quiet
mkdir -p "${HOME}/.local/bin"
tar -xzf "${tmp}/tool.tar.gz" -C "${HOME}/.local/bin" "$1"
"${HOME}/.local/bin/$1" --version
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "${HOME}/.local/bin" >> "${GITHUB_PATH}"
fi
