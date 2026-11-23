#!/bin/zsh
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$HOME/bin" "$HOME/Library/Services"

cp "$ROOT/macos/transfer-upload" "$HOME/bin/transfer-upload"
chmod 755 "$HOME/bin/transfer-upload"

for name in "Upload to Transfer (3 days).workflow" "Upload to Transfer (Forever).workflow"; do
  target="$HOME/Library/Services/$name"
  rm -rf "$target"
  cp -R "$ROOT/macos/workflows/$name" "$target"
done

/System/Library/CoreServices/pbs -flush >/dev/null 2>&1 || true
print -r -- "installed Quick Actions in ~/Library/Services"
print -r -- "next: generate an API token on https://transfer.tfworks.cn/ and run: ~/bin/transfer-upload --set-token <TOKEN>"
