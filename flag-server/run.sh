#!/usr/bin/env bash
# VEC flag server -- start it and publish it.
#
#   ./run.sh up        build and start the server (docker)
#   ./run.sh tunnel    open the ngrok tunnel and print the public URL
#   ./run.sh all       up + tunnel + repoint the player bundles
#   ./run.sh status    is it up, what URL, how many instances registered
#   ./run.sh tokens    print the register tokens
#
# Everything it needs is in this folder.
set -uo pipefail
cd "$(dirname "$0")"

PORT=8099
STATE="${VEC_STATE:-$HOME/.vec/state}"
NGROK="${NGROK_BIN:-ngrok}"
IMAGE=vec/flagserver:portable

up() {
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    CH=$(grep -v '^#' .env 2>/dev/null | sed -n 's/^VEC_CHALLENGES=//p')
    docker rm -f vec-flagserver >/dev/null 2>&1
    # The named volume is not optional. State holds every registered
    # instance, its per-instance objective value and its verification, so
    # losing it invalidates every player mid-solve -- and mints new register
    # tokens, which silently breaks the token already baked into shipped
    # handouts. This was learned the hard way.
    if docker run -d --name vec-flagserver          -p 127.0.0.1:$PORT:8099          -v vec-flagstate:/state          -e VEC_CHALLENGES="$CH"          -e VEC_ALLOW_EMPTY_TOKENS=1          vec/flagserver:portable >/dev/null 2>&1; then
      echo "[flag] container up on 127.0.0.1:$PORT (state in volume vec-flagstate)"
    else
      docker compose up -d --build
      echo "[flag] container up on 127.0.0.1:$PORT (compose)"
    fi
  else
    echo "[flag] docker unavailable, running it directly with python3"
    mkdir -p "$STATE"
    VEC_ALLOW_EMPTY_TOKENS=1 setsid python3 flag_server.py \
      --port $PORT --state "$STATE" --bind 127.0.0.1 \
      --challenges "$(grep -v '^#' .env 2>/dev/null | \
                     sed -n 's/^VEC_CHALLENGES=//p')" \
      > "$HOME/.vec/flagserver.log" 2>&1 < /dev/null &
    disown
    echo "[flag] started, log in $HOME/.vec/flagserver.log"
  fi
  for i in $(seq 1 30); do
    curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && \
      { echo "[flag] healthy"; return 0; }
    sleep 1
  done
  echo "[flag] did not come up" >&2
  return 1
}

tunnel() {
  command -v "$NGROK" >/dev/null 2>&1 || \
    { echo "[flag] ngrok not found; set NGROK_BIN" >&2; return 1; }
  "$NGROK" http $PORT > /tmp/vec-ngrok.log 2>&1 &
  disown
  for i in $(seq 1 20); do
    U=$(curl -fsS http://127.0.0.1:4040/api/tunnels 2>/dev/null | \
        python3 -c "import json,sys;print(json.load(sys.stdin)['tunnels'][0]['public_url'])" \
        2>/dev/null)
    [ -n "$U" ] && break
    sleep 1
  done
  if [ -z "$U" ]; then
    echo "[flag] tunnel did not come up; see /tmp/vec-ngrok.log" >&2
    return 1
  fi
  mkdir -p "$HOME/.vec"
  echo "$U" > "$HOME/.vec/flag_server_url"
  echo "READY $U"
}

repoint() {
  if [ -d player-bundles ] && [ -f /opt/vec/make_player_bundles.py ]; then
    VEC_PUBLIC_FLAG_URL="$(cat "$HOME/.vec/flag_server_url")" \
      python3 /opt/vec/make_player_bundles.py player-bundles
  elif [ -d player-bundles ]; then
    echo "[flag] player-bundles/ present; repoint the .env files to:"
    cat "$HOME/.vec/flag_server_url"
  fi
}

case "${1:-all}" in
  up) up ;;
  tunnel) tunnel ;;
  all) up && tunnel && repoint ;;
  status)
    curl -fsS --max-time 5 "http://127.0.0.1:$PORT/healthz" && echo
    echo "public: $(cat "$HOME/.vec/flag_server_url" 2>/dev/null || echo none)"
    ;;
  tokens) docker exec vec-flagserver cat /state/register_tokens.json 2>/dev/null \
            || cat "$HOME/.vec/state/register_tokens.json" 2>/dev/null ;;
  *) up && tunnel && repoint ;;
esac
