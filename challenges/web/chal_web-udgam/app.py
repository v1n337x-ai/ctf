#!/usr/bin/env python3
"""Velammal Engineering College CTF WEB02 -- "Udgam"

Unclaimed-deposits portal for the Prithvi cooperative bank. Session tokens are
JWTs, and the verifier trusts the token's own header.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import sys
import time
import urllib.parse
import urllib.request

PLAYER_PORT = int(os.environ.get("PLAYER_PORT", "8080"))
FLAG_SERVER = os.environ.get("FLAG_SERVER_URL", "").rstrip("/")
# Bootstrap credential for the flag server's register endpoint. Injected
# at RUN time; never baked into an image layer.
REGISTER_TOKEN = os.environ.get("VEC_REGISTER_TOKEN", "")
CHAL_ID = os.environ.get("CHAL_ID", "WEB02")
STATE_DIR = os.environ.get("STATE_DIR", "/app/state")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
OUTCOME = os.path.join(STATE_DIR, "outcome.txt")


def load_state():
    try:
        with open(STATE_FILE) as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_state(st):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(STATE_FILE, "w") as fh:
        json.dump(st, fh)


def boot():
    st = load_state()
    if st.get("instance_id"):
        # A restart, not a first run. The objective lives in a module global
        # that died with the previous process, so re-apply it from the state
        # file. Without this the challenge cannot be completed after a
        # restart: the vulnerability leaks an empty value and /verify refuses.
        if st.get("objective_value"):
            set_objective(st["objective_value"])
        return st
    st = {"instance_id": os.urandom(8).hex(), "challenge_secret": "",
          "flag": ""}
    save_state(st)
    if not FLAG_SERVER:
        print("[WEB02] FLAG_SERVER_URL unset - offline, no flag issued",
              file=sys.stderr)
        return st
    body = json.dumps({"challenge_id": CHAL_ID,
                       "instance_id": st["instance_id"]}).encode()
    try:
        req = urllib.request.Request(FLAG_SERVER + "/api/v1/register",
                                     data=body, method="POST")
        req.add_header("X-Vec-Register-Token", REGISTER_TOKEN)
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.loads(r.read())
        st["challenge_secret"] = d["challenge_secret"]
        if d.get("objective_value"):
            set_objective(d["objective_value"])
            st["objective_value"] = d["objective_value"]
        # The flag server deliberately does NOT return the flag here. It is
        # released only by /api/v1/complete once this instance proves it met
        # the objective with a valid HMAC. Nothing is cached at boot.
        st["flag"] = ""
        save_state(st)
        print("[WEB02] registered " + st["instance_id"], file=sys.stderr)
    except Exception as exc:
        print("[WEB02] registration failed: " + str(exc), file=sys.stderr)
    return st


def sign(st, proof):
    key = bytes.fromhex(st.get("challenge_secret", ""))
    msg = ("%s.%s.%s" % (CHAL_ID, st["instance_id"], proof)).encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def evidence_digest(evidence):
    return hashlib.sha256(json.dumps(evidence, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def verify(st, evidence):
    """Submit what the challenge disclosed; the server decides.

    The flag server compares the evidence against the objective value it
    issued to this instance at registration. That value was minted per
    instance and is not in the shipped files, so the only way to produce it is
    to make the challenge leak it.
    """
    if not FLAG_SERVER or not st.get("challenge_secret"):
        return None
    dg = evidence_digest(evidence)
    body = json.dumps({"challenge_id": CHAL_ID,
                       "instance_id": st["instance_id"],
                       "evidence": evidence}).encode()
    req = urllib.request.Request(FLAG_SERVER + "/api/v1/verify",
                                 data=body, method="POST")
    req.add_header("X-Vec-Signature", sign(st, dg))
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read()).get("flag")
    except Exception as exc:
        print("[WEB02] flag request failed: " + str(exc), file=sys.stderr)
        return None


def claim_flag(st):
    """Re-fetch a flag already earned for this instance.

    Verification belongs to the instance, not to the request, so a dropped
    tunnel during the flag fetch does not cost the player their solve.
    """
    if not FLAG_SERVER or not st.get("objective_met"):
        return None
    url = (FLAG_SERVER + "/api/v1/claim?challenge_id=" + CHAL_ID +
           "&instance_id=" + st["instance_id"])
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            return json.loads(r.read()).get("flag")
    except Exception:
        return None


def finish(st, evidence, extra=None):
    """Shared completion path: claim the flag, persist it, return it."""
    st["objective_met"] = True
    flag = verify(st, evidence)
    if not flag:
        flag = claim_flag(st)
    if flag:
        st["flag"] = flag
        save_state(st)
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(OUTCOME, "w") as fh:
            fh.write(flag + "\n")
        print("[WEB02] OBJECTIVE MET " + st["instance_id"], flush=True)
    payload = {"objective": "complete", "flag": st.get("flag")}
    if extra:
        payload.update(extra)
    return payload


# The portal's session signing key. Knowing it is part of the
# challenge, not the answer -- the restricted record below is.
TOKEN_SECRET = b"udgam-session-key-v1"
RECORDS = {
    "UDRN-4411902": {"name": "Ramesh Iyer", "city": "Nagpur",
                     "bank": "PRITHVI COOP", "amount": 128400,
                     "restricted": ""},
    "UDRN-4411903": {"name": "Lata Menon", "city": "Kochi",
                     "bank": "SEVA PAY", "amount": 84000,
                     "restricted": "addr: 8B Tea Estate, Kochi 682001"},
    "UDRN-4411904": {"name": "Imtiaz Khan", "city": "Guwahati",
                     "bank": "PRITHVI COOP", "amount": 51200,
                     "restricted": "addr: 3B Residency, Guwahati 781005"},
}


def set_objective(value):
    """This instance's protected record, issued by the flag server.

    It replaces the restricted field on the record the signed-in reader should
    never reach, so the only way to learn it is to make the portal return it.
    """
    RECORDS["UDRN-4411902"]["restricted"] = value


def b64u(d):
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue(payload, alg="HS256"):
    hdr = b64u(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    body = b64u(json.dumps(payload).encode())
    signing = (hdr + "." + body).encode()
    if alg == "none":
        return hdr + "." + body + "."
    sig = b64u(hmac.new(TOKEN_SECRET, signing, hashlib.sha256).digest())
    return hdr + "." + body + "." + sig


def decode(tok):
    parts = tok.split(".")
    if len(parts) < 2:
        return None, None
    try:
        return (json.loads(b64u_dec(parts[0])),
                json.loads(b64u_dec(parts[1])))
    except Exception:
        return None, None


def page(title, body):
    return ("<!doctype html><meta charset=utf-8><title>" + title + "</title>"
            "<body style=\"font-family:monospace;max-width:54em;margin:2em\">"
            "<h1>" + title + "</h1>" + body + "</body>")


def handle(cur, verb, u, q, body, H):
    if verb == "GET" and u.path == "/healthz":
        return H._json(200, {"ok": True, "service": "udgam"})

    if verb == "GET" and u.path == "/":
        return H._send(200, page("Udgam",
            "<p>Unclaimed deposits portal.</p>"
            "<p><a href='/api/v1/token/demo'>reader token</a></p>"
            "<form method=GET action='/api/v1/search'>"
            "<p>UDRN <input name=udrn value='UDRN-4411902' size=16></p>"
            "<p>token <input name=token size=44></p>"
            "<p><input type=submit value=search></p></form>"))

    if verb == "GET" and u.path == "/api/v1/token/demo":
        return H._json(200, {"token": issue({"role": "reader",
                                             "sub": "public"})})

    if verb == "GET" and u.path == "/api/v1/search":
        rec = RECORDS.get(q.get("udrn", ""))
        if not rec:
            return H._json(404, {"error": "no_such_record"})
        hdr, claims = decode(q.get("token", ""))
        if not claims:
            return H._json(401, {"error": "invalid_token"})
        alg = (hdr or {}).get("alg", "HS256")
        if alg != "none":
            return H._json(403, {"error": "insufficient_scope",
                                 "detail": "reader tokens may only read the "
                                           "published columns"})
        out = {"name": rec["name"], "city": rec["city"],
               "bank": rec["bank"], "amount": rec["amount"]}
        if claims.get("role") == "admin":
            # The restricted field of the row the unsigned admin token
            # reached. That is what the server's verifier checks.
            ev = {"restricted_record": rec["restricted"]}
            return H._json(200, dict(out, restricted=rec["restricted"],
                                     **finish(cur, ev)))
        return H._json(200, out)

    return None

# ------------------------------------------------------------------ http ---
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


# ---------------------------------------------------------------------------
# Flag-server transport shim.
#
# wargames.digialert.com sits behind Cloudflare, which answers error 1010 --
# a 403 -- to Python's default urllib agent. Every request to the flag server
# must therefore identify itself, or registration, verification and flag
# collection are all refused.
#
# Wrapping Request rather than editing the three call sites covers all of
# them, including the one that passes a bare URL to urlopen(). Only requests
# aimed at FLAG_SERVER are affected; the challenge's internal calls are not.
# ---------------------------------------------------------------------------
_real_request = urllib.request.Request


def _vec_request(url, *a, **kw):
    req = _real_request(url, *a, **kw)
    try:
        if str(getattr(req, "full_url", "")).startswith(FLAG_SERVER):
            req.add_header("User-Agent",
                           "Mozilla/5.0 (X11; Linux x86_64) "
                           "VEC-challenge/1.0")
    except Exception:
        pass
    return req


urllib.request.Request = _vec_request
# ---------------------------------------------------------------------------


def serve():
    boot()
    cur = load_state()

    class Main(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):
            print("[WEB02] " + self.address_string() + " " + (fmt % a),
                  flush=True)

        def _send(self, code, body, ctype="text/html; charset=utf-8"):
            raw = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            # A client that hangs up mid-response -- a closed tab, a
            # curl timeout, Ctrl-C. The response is already committed,
            # so there is nothing left to report and no reason to spam
            # the player's console with a traceback.
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError,
                    ConnectionAbortedError):
                pass
            return True
        def _json(self, code, obj):
            return self._send(code, json.dumps(obj, indent=2),
                                "application/json")

        def do_GET(self):
            self.route("GET")

        def do_POST(self):
            self.route("POST")

        def route(self, verb):
            cur = load_state()
            u = urllib.parse.urlsplit(self.path)
            q = {k: v[0] for k, v in
                 urllib.parse.parse_qs(u.query).items()}
            body = None
            if verb == "POST" and self.headers.get("Content-Length"):
                try:
                    n = int(self.headers["Content-Length"])
                    raw = self.rfile.read(n)
                except Exception:
                    raw = b""
                # Accept both JSON and form-encoded bodies, so a plain HTML
                # form post and a scripted solve take the same path.
                try:
                    body = json.loads(raw)
                except Exception:
                    body = {k: v[0] for k, v in
                            urllib.parse.parse_qs(raw.decode(
                                "utf-8", "replace")).items()} or None
            r = handle(cur, verb, u, q, body, self)
            if r is not None:
                return r
            self._json(404, {"error": "not found"})

    srv = ThreadingHTTPServer(("0.0.0.0", PLAYER_PORT), Main)
    print("[WEB02] player service on :" + str(PLAYER_PORT), flush=True)
    print("[WEB02] flag server: " + (FLAG_SERVER or "(unset - offline)"),
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    serve()
