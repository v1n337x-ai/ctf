#!/usr/bin/env python3
"""
Velammal Engineering College CTF WEB09 -- "Yesterday's Appliance"

A grid-edge substation controller that reached end of life three firmware
releases ago and was never replaced. Two findings, in the order a player meets
them:

  1. the panel still ships with the commissioning default credentials, and
  2. the diagnostics bundle endpoint deserialises operator-supplied data with
     pickle, which is remote code execution by construction.

The version banner is the hint. Everything here was written from scratch for
this campaign; no real appliance, firmware image or vendor is referenced.
"""
import base64
import hashlib
import hmac
import json
import os
import pickle
import sqlite3
import sys
import urllib.parse
import urllib.request

PLAYER_PORT = int(os.environ.get("PLAYER_PORT", "8080"))
FLAG_SERVER = os.environ.get("FLAG_SERVER_URL", "").rstrip("/")
# Bootstrap credential for the flag server's register endpoint. Injected
# at RUN time; never baked into an image layer.
REGISTER_TOKEN = os.environ.get("VEC_REGISTER_TOKEN", "")
CHAL_ID = os.environ.get("CHAL_ID", "WEB09")
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
        return st
    st = {"instance_id": os.urandom(8).hex(), "challenge_secret": "",
          "flag": ""}
    save_state(st)
    if not FLAG_SERVER:
        print("[WEB09] FLAG_SERVER_URL unset - offline, no flag issued",
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
            st["objective_value"] = d["objective_value"]
        # The flag server deliberately does NOT return the flag here. It is
        # released only by /api/v1/complete once this instance proves it met
        # the objective with a valid HMAC. Nothing is cached at boot.
        st["flag"] = ""
        save_state(st)
        print("[WEB09] registered " + st["instance_id"], file=sys.stderr)
    except Exception as exc:
        print("[WEB09] registration failed: " + str(exc), file=sys.stderr)
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
        print("[WEB09] flag request failed: " + str(exc), file=sys.stderr)
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
        print("[WEB09] OBJECTIVE MET " + st["instance_id"], flush=True)
    payload = {"objective": "complete", "flag": st.get("flag")}
    if extra:
        payload.update(extra)
    return payload


FIRMWARE = "EDGE-CTRL 2.8.4 (EOL 2023-11-02)"
DEFAULT_USER = "admin"
DEFAULT_PASS = "prithvi-commission"
KEY_FILE = os.path.join(STATE_DIR, "appliance.key")
LEAK_FILE = os.path.join(STATE_DIR, "public.txt")
DB_FILE = os.path.join(STATE_DIR, "appliance.db")


def db():
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    c = sqlite3.connect(DB_FILE)
    c.execute("""CREATE TABLE IF NOT EXISTS sessions(
                    sid TEXT PRIMARY KEY, user TEXT, created INTEGER)""")
    c.commit()
    return c


def appliance_key():
    """This instance's signing key.

    Normally the flag server issued it at registration, so it is not in the
    handout and is known only to this appliance and to the server. If the flag
    server is unreachable there is nothing to verify against, so a local key is
    generated instead and the run simply issues no flag.
    """
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE) as fh:
            return fh.read().strip()
    issued = load_state().get("objective_value") or ""
    value = issued or ("APPL-SIG-" + os.urandom(12).hex())
    os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
    with open(KEY_FILE, "w") as fh:
        fh.write(value)
    return value


def page(title, body):
    return ("<!doctype html><meta charset=utf-8><title>" + title + "</title>"
            "<body style=\"font-family:monospace;max-width:54em;margin:2em\">"
            "<h1>" + title + "</h1>" + body + "</body>")


def session_of(H):
    ck = H.headers.get("Cookie", "")
    for part in ck.split(";"):
        k, _, v = part.strip().partition("=")
        if k == "sid" and v:
            c = db()
            row = c.execute("SELECT user FROM sessions WHERE sid=?",
                            (v,)).fetchone()
            c.close()
            return row[0] if row else None
    return None


def handle(cur, verb, u, q, body, H):
    if verb == "GET" and u.path == "/healthz":
        return H._json(200, {"ok": True, "service": "edge-controller"})

    if verb == "GET" and u.path == "/":
        return H._send(200, page("Edge Controller",
            "<p>Substation edge controller.</p><p>firmware: <code>"
            + FIRMWARE + "</code></p>"
            "<p><a href='/login'>operator login</a></p>"))

    if u.path == "/login":
        if verb == "GET":
            return H._send(200, page("Operator login",
                "<form method=POST action='/login'>"
                "<p>user <input name=user value='admin'></p>"
                "<p>password <input name=password type=password></p>"
                "<p><input type=submit value=login></p></form>"))
        if verb == "POST":
            user = (body or {}).get("user", "")
            pw = (body or {}).get("password", "")
            if not (user == DEFAULT_USER and pw == DEFAULT_PASS):
                return H._json(401, {"error": "invalid_credentials"})
            sid = os.urandom(12).hex()
            c = db()
            c.execute("INSERT INTO sessions(sid,user,created) VALUES(?,?,?)",
                      (sid, user, 0))
            c.commit()
            c.close()
            H.send_response(302)
            H.send_header("Set-Cookie", "sid=" + sid + "; Path=/")
            H.send_header("Location", "/panel")
            H.send_header("Content-Length", "0")
            H.end_headers()
            return True

    user = session_of(H)
    if u.path.startswith("/panel") and not user:
        return H._json(401, {"error": "authentication_required"})

    if verb == "GET" and u.path == "/panel":
        return H._send(200, page("Controller panel",
            "<p>signed in as <b>" + str(user) + "</b></p>"
            "<h2>diagnostics</h2>"
            "<p>Upload a diagnostics bundle captured from a peer unit.</p>"
            "<form method=POST action='/panel/diagnostics'>"
            "<p>bundle (base64) <textarea name=bundle rows=6 cols=60>"
            "</textarea></p>"
            "<p><input type=submit value=upload bundle></p></form>"
            "<p><a href='/panel/status'>status</a></p>"))

    if u.path == "/panel/status":
        return H._json(200, {"firmware": FIRMWARE, "role": user,
                             "feeder": "F-114", "load_kw": 412})

    if verb == "POST" and u.path == "/panel/diagnostics":
        raw = (body or {}).get("bundle", "")
        try:
            blob = base64.b64decode(raw, validate=False)
        except Exception:
            blob = b""
        # The bundle format is the vendor's own pickle stream. Peer units are
        # trusted, so the stream is deserialised as-is.
        try:
            obj = pickle.loads(blob)
            note = "decoded %d object(s)" % 1
            err = None
        except Exception as exc:
            obj, note = None, "bundle rejected"
            err = str(exc)[:200]
        # Whatever the peer wrote during decode is now on disk.
        leaked = ""
        if os.path.exists(LEAK_FILE):
            with open(LEAK_FILE) as fh:
                leaked = fh.read().strip()
        out = {"status": "processed", "note": note}
        if err:
            out["error"] = err
        if leaked:
            out["decoded_report"] = leaked
            if leaked == appliance_key():
                return H._json(200, dict(
                    out, **finish(cur, {"appliance_key": leaked},
                                  {"artifact": "appliance.key"})))
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
    # The controller provisions its signing key at startup, so it always
    # exists on disk before any bundle is decoded.
    appliance_key()
    cur = load_state()

    class Main(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):
            print("[WEB09] " + self.address_string() + " " + (fmt % a),
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
    print("[WEB09] player service on :" + str(PLAYER_PORT), flush=True)
    print("[WEB09] flag server: " + (FLAG_SERVER or "(unset - offline)"),
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    serve()
