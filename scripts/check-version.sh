#!/usr/bin/env bash
# Fail when a release tag and .claude-plugin/plugin.json disagree. Wired into
# the release workflow so a release can never ship a mismatched manifest.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$root/.claude-plugin/plugin.json"

manifest_version="$(jq -r '.version' "$manifest")"
expected="${1#v}"

if [[ -n "$expected" && "$expected" != "$manifest_version" ]]; then
  echo "version check failed:" >&2
  echo "  release tag (${expected}) != .claude-plugin/plugin.json (${manifest_version})" >&2
  echo "Bump .claude-plugin/plugin.json before tagging a release." >&2
  exit 1
fi

echo "versions consistent: ${manifest_version}"
