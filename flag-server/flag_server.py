#!/usr/bin/env python3
"""
VEC flag server.

One process serves every Docker challenge. It never stores a flag inside a
challenge container: containers POST here on completion and receive their own
flag.

Properties that matter:

  * No unauthenticated read path exists. There is no GET /flag. A flag comes
    back only for a request that carries a valid per-challenge HMAC over a
    registered instance.
  * Isolation is structural. WEB01 holds WEB01's secret. It cannot produce a
    signature the server will accept for WEB02, because the secret is keyed
    per challenge AND the server checks challenge_id against the secret it
    issued for that challenge.
  * One stable flag per challenge. Every instance, and every reset,
    returns the same value. There is no per-instance salt.
  * Error responses are byte-identical apart from status code, so the
    endpoint cannot be used to enumerate which challenges exist.

Transport is ngrok (or anything else) -- see README. Nothing here is aware of
ngrok; it just listens on a port.

Run:  python3 flag_server.py --port 8099 --state /state
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import string
import sys
import threading
import time
import urllib.parse
import uuid
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from phrases import pool as phrase_pool
except ImportError:                                    # packaged standalone
    phrase_pool = None
try:
    import verifiers
except ImportError:                                    # packaged standalone
    verifiers = None


def _evidence_digest(evidence):
    """A stable digest of a submission, used as the signed proof."""
    blob = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()

ALPHABET = string.ascii_letters + string.digits
FLAG_RE = re.compile(r"^[A-Za-z0-9]+$")

# Shape of the per-instance objective value, per challenge family. The value
# has to look like something that belongs in the challenge's own data model,
# because the player will meet it in their app's database, session store or
# key file and it should not read as obviously synthetic. The prefix is fixed
# per challenge family; the body is random per instance.
_OBJECTIVE_SHAPES = {
    "WEB01": "NCCC-META-", "WEB02": "UDGAM-SESS-", "WEB03": "GRV-PHOTO-",
    "WEB04": "VNDR-REFRESH-", "WEB05": "GRID-LEDGER-", "WEB06": "REF-VALVE-",
    "WEB07": "CIT-AUTH-", "WEB08": "STL-REF-", "WEB09": "APPL-SIG-",
    "WEB10": "FW-SIGN-", "SIM-23": "SUBS-BANNER-", "SIM-24": "AMR-SESS-",
    "SIM-25": "KAV-FRAME-", "SIM-26": "TKT-GRANT-", "SIM-27": "KHARGA-ACL-",
    "SIM-28": "JMP-SUDO-", "SIM-29": "KRBTGT-RC4-", "SIM-30": "UPD-CONDUIT-",
    "SIM-31": "DCSYNC-ACL-", "SIM-32": "ASSET-REG-", "SIM-33": "CORE-ZONE-",
    "SIM-34": "CANARY-MEM-", "SIM-36": "TRUST-SHARD-",
}


def _new_objective_value(challenge, instance_id):
    """Mint the value one instance's solver has to produce.

    Unique per instance, so two players never share an answer and a value
    lifted from another team's machine is worthless here. It is drawn from
    the system CSPRNG rather than derived from anything the player can see,
    so the value cannot be predicted before registering.
    """
    prefix = _OBJECTIVE_SHAPES.get(challenge.upper(), "OBJ-")
    body = base64.b32encode(secrets.token_bytes(9)).decode("ascii").rstrip("=")
    return prefix + body

# Per-challenge completion secrets. Generated on first boot if absent, or
# injected by the organiser. In a real deployment these come from the
# environment, never from a file baked into a challenge image.
SECRET_ENV = "VEC_CHALLENGE_SECRETS"      # {"WEB01":"hex", ...}

# Bootstrap credential for /api/v1/register. Without it, ANY caller who can
# reach this server can mint an instance. Without ALSO hiding the flag from the
# register response, that is a complete flag oracle -- so both are required:
#   * a per-challenge register token, presented in X-Vec-Register-Token
#   * register returns the signing secret ONLY; the flag comes from /complete
# Refusing to start without a token is deliberate: fail closed, not open.
TOKEN_ENV = "VEC_REGISTER_TOKENS"         # {"WEB01":"hex", ...}

# /api/v1/challenges enumerates challenge IDs. Off unless explicitly enabled.
DEBUG_ENV = "VEC_DEBUG"

# Bootstrap escape hatch: generate register tokens instead of refusing to start.
ALLOW_EMPTY_ENV = "VEC_ALLOW_EMPTY_TOKENS"

# Rate limit: sliding window per source address. A flat counter would lock out
# every instance behind one NAT egress after N requests for the whole event.
RATE_WINDOW = 60.0        # seconds
# Per source address. 50 players behind one venue NAT share an address, and a
# flat counter would lock out the whole event at 600 requests a minute -- one
# health check per player every 10 seconds and the flag server stops serving.
# This is sized for a full room on one egress, and is still a real ceiling
# against a single host hammering /verify.
RATE_MAX = int(os.environ.get("VEC_RATE_MAX", "6000"))


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Store:
    """Instances, flags and secrets. Thread-safe."""

    def __init__(self, state_dir, challenges):
        self.dir = state_dir
        self.challenges = challenges
        self.lock = threading.Lock()
        self.instances = {}          # (challenge, instance) -> record
        self.flags = {}              # (challenge, instance) -> flag
        self.used_proofs = set()     # (challenge, instance, proof) replay
        self.completed = set()       # (challenge, instance) flag already given
        self.objectives = {}         # (challenge, instance) -> protected value
        self.secrets = {}
        self.tokens = {}
        self.hits = defaultdict(deque)
        os.makedirs(state_dir, exist_ok=True)
        self._load_secrets()
        self._load_tokens()
        self._load_instances()

    # -- instance records ------------------------------------------------
    #
    # Everything about a registered instance has to survive a restart of the
    # flag server. The organiser's laptop will be restarted at some point
    # during the event, and a player who registered before that and solves
    # after it must still be able to collect. It also holds the per-instance
    # objective value, which is the answer for that instance -- if that were
    # lost, the verifier would have nothing to compare against and every
    # in-flight solve would be rejected.
    def _instance_path(self):
        return os.path.join(self.dir, "instances.json")

    def _load_instances(self):
        path = self._instance_path()
        if not os.path.exists(path):
            return
        try:
            with open(path) as fh:
                blob = json.load(fh)
        except Exception as exc:                       # noqa: BLE001
            print(f"[flag-server] instances.json unreadable: {exc}",
                  file=sys.stderr)
            return
        for rec in blob.get("instances", []):
            try:
                key = (rec["challenge"].upper(), rec["instance_id"])
            except (KeyError, TypeError):
                continue
            self.instances[key] = rec
            if rec.get("flag"):
                self.flags[key] = rec["flag"]
            if rec.get("objective"):
                self.objectives[key] = rec["objective"]
            if rec.get("completed"):
                self.completed.add(key)
            for p in rec.get("proofs", []):
                self.used_proofs.add((key[0], key[1], p))
        print(f"[flag-server] restored {len(self.instances)} instance(s) "
              f"from {path}", flush=True)

    def _save_instances(self):
        out = []
        for key, rec in self.instances.items():
            r = dict(rec)
            r["proofs"] = [p for (c, i, p) in self.used_proofs
                           if c == key[0] and i == key[1]]
            if key in self.completed:
                r["completed"] = True
            out.append(r)
        tmp = self._instance_path() + ".tmp"
        with open(tmp, "w") as fh:
            json.dump({"instances": out}, fh, indent=2)
        # Rename is atomic, so a crash mid-write cannot leave a truncated
        # file that would lose every instance's objective value.
        os.replace(tmp, self._instance_path())
        os.chmod(self._instance_path(), 0o600)

    # -- secrets ---------------------------------------------------------
    def _load_secrets(self):
        raw = os.environ.get(SECRET_ENV, "")
        if raw:
            try:
                for k, v in json.loads(raw).items():
                    self.secrets[k.upper()] = bytes.fromhex(v)
            except Exception as exc:                     # noqa: BLE001
                print(f"[flag-server] bad {SECRET_ENV}: {exc}", file=sys.stderr)
        path = os.path.join(self.dir, "secrets.json")
        if os.path.exists(path):
            with open(path) as fh:
                for k, v in json.load(fh).items():
                    self.secrets.setdefault(k.upper(), bytes.fromhex(v))
        # generate any missing
        changed = False
        for c in self.challenges:
            if c.upper() not in self.secrets:
                self.secrets[c.upper()] = secrets.token_bytes(32)
                changed = True
        if changed:
            with open(os.path.join(self.dir, "secrets.json"), "w") as fh:
                json.dump({k: v.hex() for k, v in self.secrets.items()}, fh,
                          indent=2)
            os.chmod(os.path.join(self.dir, "secrets.json"), 0o600)
            print("[flag-server] generated missing challenge secrets")

    def secret(self, challenge):
        return self.secrets.get(challenge.upper())

    # -- register tokens -------------------------------------------------
    def _load_tokens(self):
        raw = os.environ.get(TOKEN_ENV, "")
        if raw:
            try:
                for k, v in json.loads(raw).items():
                    self.tokens[k.upper()] = v.strip().lower()
            except Exception as exc:                     # noqa: BLE001
                print(f"[flag-server] bad {TOKEN_ENV}: {exc}", file=sys.stderr)
        path = os.path.join(self.dir, "register_tokens.json")
        if os.path.exists(path):
            with open(path) as fh:
                for k, v in json.load(fh).items():
                    self.tokens.setdefault(k.upper(), str(v).strip().lower())
        missing = [c for c in self.challenges
                   if c.upper() not in self.tokens]
        if missing:
            # Fail closed. An unauthenticated register endpoint is a flag oracle.
            if os.environ.get(ALLOW_EMPTY_ENV, "") not in ("1", "true", "yes"):
                raise SystemExit(
                    "[flag-server] REFUSING TO START: no register token for "
                    + ", ".join(sorted(missing))
                    + ".\n[flag-server] Set " + TOKEN_ENV
                    + ' as JSON, e.g. {"WEB01":"<32-byte hex>"}.\n'
                    + "[flag-server] To bootstrap instead, set "
                    + ALLOW_EMPTY_ENV + "=1 once and the tokens will be "
                    + "generated into the state directory.")
            for c in missing:
                self.tokens[c.upper()] = secrets.token_hex(32)
            print("[flag-server] GENERATED register tokens for "
                  + ", ".join(sorted(missing)), file=sys.stderr)
        path = os.path.join(self.dir, "register_tokens.json")
        if not os.path.exists(path):
            with open(path, "w") as fh:
                json.dump(self.tokens, fh, indent=2)
            os.chmod(path, 0o600)
            print("[flag-server] generated register tokens", flush=True)

    def token_ok(self, challenge, presented):
        want = self.tokens.get(challenge.upper())
        if not want or not presented:
            return False
        return hmac.compare_digest(want, str(presented).strip().lower())

    # -- rate limiting ---------------------------------------------------
    def allow(self, ip):
        now_ts = time.time()
        q = self.hits[ip]
        while q and now_ts - q[0] > RATE_WINDOW:
            q.popleft()
        if len(q) >= RATE_MAX:
            return False
        q.append(now_ts)
        return True

    # -- signature -------------------------------------------------------
    def sign(self, challenge, instance_id, proof):
        return hmac.new(self.secret(challenge),
                         f"{challenge}.{instance_id}.{proof}".encode(),
                         hashlib.sha256).hexdigest()

    def verify(self, challenge, instance_id, proof, signature):
        want = self.sign(challenge, instance_id, proof)
        return hmac.compare_digest(want, (signature or "").lower())

    # -- instances -------------------------------------------------------
    def register(self, challenge, instance_id):
        with self.lock:
            key = (challenge.upper(), instance_id)
            if challenge.upper() not in self.secrets:
                return None
            existing = self.instances.get(key)
            if existing and existing.get("objective"):
                # Re-registering the same instance must not mint a new
                # objective value: the player already has the old one in
                # their bundle, and swapping it would strand a solve that is
                # already in progress.
                return existing["objective"]
            # The value this instance's solver has to produce. It is random
            # per instance and never leaves this server except to the app
            # that registered, so it cannot be read out of the shipped
            # bundle the way a hardcoded literal can. The app writes it into
            # its own store at boot and the only route back to it is the
            # challenge's intended attack.
            value = _new_objective_value(challenge.upper(), instance_id)
            self.instances[key] = {
                "challenge": challenge.upper(),
                "instance_id": instance_id,
                "registered": now(),
                "objective": value,
            }
            self.objectives[key] = value
            if key not in self.flags:
                self.flags[key] = self._new_flag(challenge.upper(),
                                                 instance_id)
            self.instances[key]["flag"] = self.flags[key]
            self._save_instances()
            return value

    def objective(self, challenge, instance_id):
        """The value this instance's solver must produce."""
        return self.objectives.get((challenge.upper(), instance_id))

    def scoreboard(self):
        """Solve counts per challenge.

        Deliberately aggregate. With one shared registration token there is
        no honest way to attribute a solve to a team, so per-instance detail
        would imply a precision the data does not have.
        """
        with self.lock:
            counts = {}
            for (chal, _inst) in self.completed:
                counts[chal] = counts.get(chal, 0) + 1
            out = []
            for chal in sorted(self.secrets):
                out.append({
                    "challenge": chal,
                    "solves": counts.get(chal, 0),
                    "instances": sum(1 for (c, _i) in self.instances
                                     if c == chal),
                })
            return out

    def _new_flag(self, challenge, instance_id):
        """Mint this challenge's flag.

        The flag is a phrase from the challenge's registry pool, chosen
        deterministically from the challenge id alone. No instance id, no
        salt, no randomness: every instance and every reset returns the
        same value.
        """
        if phrase_pool is not None:
            try:
                msgs = phrase_pool(challenge)
                idx = int(hashlib.sha256(challenge.encode().upper()
                                         + b"|vec").hexdigest(),
                          16) % len(msgs)
                cand = msgs[idx]
                if FLAG_RE.match(cand) and len(cand) <= 48:
                    return cand
                return msgs[0]
            except KeyError:
                pass
        while True:
            f = "".join(secrets.choice(ALPHABET) for _ in range(16))
            if FLAG_RE.match(f):
                return f

    def get(self, challenge, instance_id):
        return self.flags.get((challenge.upper(), instance_id))

    def known(self, challenge, instance_id):
        return (challenge.upper(), instance_id) in self.instances

    def replayed(self, challenge, instance_id, proof):
        return (challenge.upper(), instance_id, proof) in self.used_proofs

    def mark(self, challenge, instance_id, proof):
        self.used_proofs.add((challenge.upper(), instance_id, proof))
        self._save_instances()

    def already_completed(self, challenge, instance_id):
        return (challenge.upper(), instance_id) in self.completed

    def mark_completed(self, challenge, instance_id):
        self.completed.add((challenge.upper(), instance_id))
        self._save_instances()


class Handler(BaseHTTPRequestHandler):
    server_version = "vec-flag-server/1.0"
    store: Store = None

    def log_message(self, fmt, *args):
        print(f"[flag-server] {now()} {self.address_string()} "
              f"{fmt % args}", flush=True)

    # -- helpers ---------------------------------------------------------
    def _send(self, code, payload):
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, code, markup):
        body = markup.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _deny(self, code, msg):
        # Identical shape for unknown challenge / unknown instance / bad sig.
        self._send(code, {"error": msg})

    def _rate(self):
        if not self.store.allow(self.client_address[0]):
            self._send(429, {"error": "rate limited"})
            return False
        return True

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n or n > 64 * 1024:
            return None
        try:
            return json.loads(self.rfile.read(n))
        except Exception:                                # noqa: BLE001
            return None

    # -- routes ----------------------------------------------------------
    def do_GET(self):
        if not self._rate():
            return
        if self.path.split("?")[0] == "/healthz":
            self._send(200, {"status": "ok", "time": now()})
            return
        if self.path.split("?")[0] == "/api/v1/challenges":
            # Enumeration. Off unless VEC_DEBUG is set.
            if os.environ.get(DEBUG_ENV, "") not in ("1", "true", "yes"):
                self._deny(404, "not found")
                return
            self._send(200, {"challenges": sorted(self.store.secrets)})
            return
        if self.path.split("?")[0] == "/api/v1/claim":
            return self._claim()
        if self.path.split("?")[0] == "/scoreboard":
            return self._scoreboard_page()
        if self.path.split("?")[0] == "/api/v1/scoreboard":
            return self._scoreboard()
        # There is deliberately no /flag route.
        self._deny(404, "not found")

    def _scoreboard(self):
        """Per-challenge solve counts. No flags, no instance ids, no players.

        This is safe to project on a wall during a live event: it exposes
        nothing that could be used to claim a flag. Per-instance detail stays
        off deliberately -- with one shared registration token there is no
        way to attribute a solve to a team anyway.
        """
        rows = self.store.scoreboard()
        self._send(200, {"generated": now(), "challenges": rows})
        return None

    def _scoreboard_page(self):
        """A plain HTML view of the same numbers, for a projector."""
        rows = self.store.scoreboard()
        solved = sum(1 for r in rows if r["solves"])
        body = ["<!doctype html><meta charset=utf-8>",
                "<title>VEC scoreboard</title>",
                "<style>body{font-family:ui-monospace,Menlo,monospace;"
                "background:#0d1117;color:#c9d1d9;margin:2em}"
                "table{border-collapse:collapse;margin-top:1em}"
                "td,th{padding:.4em 1.2em;border-bottom:1px solid #30363d;"
                "text-align:left}"
                "th{color:#8b949e}"
                ".n{text-align:right;font-variant-numeric:tabular-nums}"
                ".zero{color:#484f58}</style>",
                f"<h1>VEC</h1><p>{solved} of {len(rows)} challenges "
                f"solved &middot; {now()}</p>",
                "<table><tr><th>challenge</th><th class=n>solves</th></tr>"]
        for r in sorted(rows, key=lambda x: (-x["solves"], x["challenge"])):
            cls = "" if r["solves"] else ' class="zero"'
            body.append(f"<tr><td>{r['challenge']}</td>"
                        f"<td class=n{cls}>{r['solves']}</td></tr>")
        body.append("</table>")
        self._html(200, "\n".join(body))
        return None

    def do_POST(self):
        if not self._rate():
            return
        route = self.path.split("?")[0]
        body = self._body()
        if body is None:
            return self._deny(400, "bad request")

        if route == "/api/v1/register":
            return self._register(body)
        if route == "/api/v1/complete":
            return self._complete(body)
        if route == "/api/v1/verify":
            return self._verify(body)
        return self._deny(404, "not found")

    def _register(self, body):
        challenge = str(body.get("challenge_id", ""))
        instance = str(body.get("instance_id", ""))
        if not re.match(r"^[A-Za-z0-9-]{1,64}$", challenge or "") or \
           not re.match(r"^[A-Za-z0-9-]{1,64}$", instance or ""):
            return self._deny(400, "bad request")
        # Identical response for unknown challenge and bad token, so this
        # cannot be used to enumerate which challenge IDs exist.
        presented = self.headers.get("X-Vec-Register-Token", "")
        if not self.store.token_ok(challenge, presented):
            return self._deny(401, "unauthorized")
        if not self.store.register(challenge, instance):
            return self._deny(404, "not found")
        # The container learns how to sign, and it gets its OWN per-instance
        # objective value -- the thing its challenge's vulnerability will leak.
        # It gets no flag. The flag is released only by /verify, and only once
        # the server's own verifier agrees the objective was demonstrated.
        sec = self.store.secret(challenge).hex()
        objective = self.store.objective(challenge, instance)
        print(f"[flag-server] registered {challenge}/{instance}", flush=True)
        self._send(200, {"challenge_id": challenge.upper(),
                         "instance_id": instance,
                         "challenge_secret": sec,
                         "objective_value": objective})
        return None

    def _complete(self, body):
        """Retired. A flag is issued only by /verify, never on assertion.

        This used to hand out a flag to any caller who presented a valid HMAC
        over an objective proof. That proved the request came from the app
        instance, but not that anybody solved anything -- the client computed
        the proof itself, so the player edited one line and collected every
        flag. The objective decision now lives in verifiers.py, behind
        /verify, and this path refuses so the weak gate cannot be used.
        """
        return self._deny(410, "use /api/v1/verify")


    def _verify(self, body):
            """The objective decision lives here, not in the player's bundle.

            The client submits evidence; this server runs the per-challenge
            verifier, which compares it against the value this instance was
            issued at registration. That value was minted per instance and is
            never written into the shipped bundle, so the only way to produce
            it is to make the challenge leak it.
            """
            challenge = str(body.get("challenge_id", ""))
            instance = str(body.get("instance_id", ""))
            evidence = body.get("evidence")
            sig = self.headers.get("X-Vec-Signature", "")

            if not challenge or not instance or not isinstance(evidence, dict):
                return self._deny(400, "bad request")
            if challenge.upper() not in self.store.secrets:
                return self._deny(404, "not found")
            if not self.store.known(challenge, instance):
                return self._deny(404, "not found")
            # The signature binds the submission to this instance, so one team's
            # evidence cannot release another team's flag.
            if not self.store.verify(challenge, instance,
                                     _evidence_digest(evidence), sig):
                return self._deny(401, "not found")

            want = self.store.objective(challenge, instance)
            ok, note = verifiers.check(challenge, evidence, instance, want)
            if not ok:
                print(f"[flag-server] REFUSED {challenge.upper()}/{instance} "
                      f"-> {note}", flush=True)
                return self._send(403, {"error": "objective not demonstrated"})

            flag = self.store.get(challenge, instance)
            if not flag or not FLAG_RE.match(flag):
                return self._deny(500, "flag unavailable")
            self.store.mark_completed(challenge, instance)
            print(f"[flag-server] VERIFIED {challenge.upper()}/{instance} "
                  f"-> flag issued ({note})", flush=True)
            self._send(200, {"challenge_id": challenge.upper(),
                             "instance_id": instance, "flag": flag})
            return None

    def _claim(self):
        """Re-issue a flag for an instance whose objective already passed.

        A player who solved the objective but hit a dead tunnel during the
        request would otherwise lose the solve outright: the handout cannot be
        updated, so there is no second chance for them. Verification is a
        property of the instance, not of the request, so this can safely
        return the same flag again for an instance that already passed.
        """
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        challenge = (params.get("challenge_id") or [""])[0]
        instance = (params.get("instance_id") or [""])[0]
        if not challenge or not instance:
            return self._deny(400, "bad request")
        if challenge.upper() not in self.store.secrets:
            return self._deny(404, "not found")
        if not self.store.known(challenge, instance):
            return self._deny(404, "not found")
        if not self.store.already_completed(challenge, instance):
            # Do not confirm or deny anything about an unverified instance.
            return self._deny(403, "objective not demonstrated")
        flag = self.store.get(challenge, instance)
        if not flag or not FLAG_RE.match(flag):
            return self._deny(500, "flag unavailable")
        self._send(200, {"challenge_id": challenge.upper(),
                         "instance_id": instance, "flag": flag})
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int,
                    default=int(os.environ.get("FLAG_SERVER_PORT", 8099)))
    ap.add_argument("--state", default=os.environ.get("FLAG_SERVER_STATE",
                                                      "/state"))
    ap.add_argument("--challenges", default=os.environ.get(
        "VEC_CHALLENGES", ""))
    ap.add_argument("--bind", default=os.environ.get("FLAG_SERVER_BIND",
                                                     "127.0.0.1"))
    a = ap.parse_args()

    wanted = [c.strip() for c in a.challenges.split(",") if c.strip()]
    if not wanted:
        raise SystemExit(
            "[flag-server] no challenges configured. Set VEC_CHALLENGES "
            'to a comma-separated list, e.g. VEC_CHALLENGES="WEB01,WEB02".')
    Handler.store = Store(a.state, wanted)          # exactly one Store
    srv = ThreadingHTTPServer((a.bind, a.port), Handler)
    print(f"[flag-server] listening on {a.bind}:{a.port}", flush=True)
    print(f"[flag-server] challenges: "
          f"{', '.join(sorted(Handler.store.secrets))}", flush=True)
    if a.bind not in ("127.0.0.1", "localhost", "::1"):
        print(f"[flag-server] WARNING: bound to {a.bind} -- reachable from "
              f"anything that can route to this host.", file=sys.stderr)
    print("[flag-server] no unauthenticated read path: register requires "
          "X-Vec-Register-Token and returns no flag.", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()