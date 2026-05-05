#!/usr/bin/env bash
set -euo pipefail

git config core.hooksPath .githooks
chmod +x .githooks/pre-commit .githooks/pre-push scripts/security-audit.sh
echo "core.hooksPath=.githooks"
