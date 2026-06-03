#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "============================================"
echo "  Auth Proxy Bridge — Starting..."
echo "============================================"
echo "  Config: proxy_config.json"
echo

exec python auth_proxy.py
