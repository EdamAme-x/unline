#!/usr/bin/env bash
set -euo pipefail

blocked_paths='(^|/)(www|dist|secret|\.cache)(/|$)|(^|/)\.env(\.|$)|\.(pem|key|crt|p12|pfx|crx|zip)$'

status=0

while IFS= read -r -d '' file; do
  [[ "$file" == ".env.example" ]] && continue
  if [[ "$file" =~ $blocked_paths ]]; then
    echo "blocked tracked path: $file" >&2
    status=1
  fi
done < <(git ls-files -z)

if ! command -v gitleaks >/dev/null 2>&1; then
  if [[ -x "$HOME/go/bin/gitleaks" ]]; then
    GITLEAKS_BIN="$HOME/go/bin/gitleaks"
  else
    echo "gitleaks is required for secret scanning." >&2
    echo "Install example: go install github.com/zricethezav/gitleaks/v8@v8.24.3" >&2
    exit 127
  fi
else
  GITLEAKS_BIN="$(command -v gitleaks)"
fi

"$GITLEAKS_BIN" detect --source . --no-git --redact --no-banner
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  "$GITLEAKS_BIN" detect --source . --redact --no-banner
fi
exit "$status"
