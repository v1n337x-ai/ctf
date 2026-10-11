#!/usr/bin/env bash
# SIM-37 -- run it locally.
#
#   ./run.sh
#
# Everything is in this folder. The flag is not: it comes from the campaign
# flag server when you complete the objective, and this script already knows
# where that is.
set -euo pipefail
cd "$(dirname "$0")"
set -a; . ./.env; set +a

echo "[SIM-37] flag server : ${FLAG_SERVER_URL}"

# Preflight. A player should learn the flag server is unreachable now, not
# after an hour of solving. This does not block startup: the challenge is
# still fully playable offline, and a solve made offline is claimed the
# moment the server comes back.
if command -v curl >/dev/null 2>&1; then
  if curl -fsS --max-time 8 "${FLAG_SERVER_URL}/healthz" >/dev/null 2>&1; then
    echo "[SIM-37] flag server reachable -- solving will earn a flag"
  else
    echo "[SIM-37] WARNING: cannot reach the flag server right now." >&2
    echo "[SIM-37]   You can still solve. Your flag is claimed automatically" >&2
    echo "[SIM-37]   once the server is reachable again -- nothing is lost." >&2
  fi
fi


if [ -f app.py ]; then
  exec python3 -u app.py
fi
echo "no app.py in this bundle" >&2
exit 1
