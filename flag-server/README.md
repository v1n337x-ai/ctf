# VEC flag server -- portable

One folder, one command. Run it on the venue machine or your laptop; it
serves every challenge's flags and publishes itself through your ngrok
tunnel. Players' bundles already point at the URL below, so the connection
is automatic.

## This deployment's fixed public URL

    https://dangle-rescuer-greedy.ngrok-free.dev

That is a **reserved ngrok domain**, not a random per-restart URL, and it
is already baked into all 23 player bundles. It comes back identical after a
restart, so nothing a player was given goes stale. Do not change it without
rebuilding the bundles.

## First run

    cp .env.example .env        # list the challenges you are running
    ./run.sh all                # build, start, tunnel

    READY https://dangle-rescuer-greedy.ngrok-free.dev

Check it is alive before you tell anyone to play:

    curl -s https://dangle-rescuer-greedy.ngrok-free.dev/healthz

## Live views during the event

    /scoreboard                  a page you can put on a projector
    /api/v1/scoreboard           the same numbers as JSON

Both show solve counts per challenge only -- no flags, no player detail.

## The other commands

    ./run.sh up        start (or restart) the server
    ./run.sh tunnel    just the ngrok tunnel, prints the URL
    ./run.sh status    health, current public URL
    ./run.sh tokens    the per-challenge register tokens

## What is in here

    flag_server.py    the API: register, verify, claim, scoreboard
    verifiers.py      per-challenge objective decisions -- the gate
    phrases.py        the flag phrase registry
    Dockerfile        the image (python base only)
    docker-compose.yml
    run.sh            the commands above
    player-bundles/   the challenges players run, if you copied them here

## Things that will bite you

- The server binds **127.0.0.1** on purpose. Reach it through the tunnel.
  Do not publish 8099 on your LAN.
- `VEC_ALLOW_EMPTY_TOKENS=1` is bootstrap only. Once the state volume
  has tokens, set it to 0 so the server refuses to start without them.
- `VEC_RATE_MAX` defaults to 6000 requests a minute **per source
  address**. A full room behind one venue NAT shares an address, so this
  must stay high; the first event setting was 600 and it locked the room
  out.
- **Rotate the ngrok authtoken before the event** if it has ever been
  pasted anywhere public.
- Stopping the container does not lose state: it is in a named volume. A
  player mid-solve keeps their objective value across a restart, and
  verification is a property of their instance, so a solve earned before a
  crash can be collected afterwards with /api/v1/claim.
- **Leave this machine awake for the whole event.** The bundles warn the
  player if the flag server is unreachable, but a sleeping machine stops new
  solves entirely.
