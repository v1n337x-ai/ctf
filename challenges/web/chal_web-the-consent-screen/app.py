#!/usr/bin/env python3
"""
Velammal Engineering College CTF WEB07 -- "The Consent Screen"

OAuth 2.0 authorisation-code flow against the Prithvi Udyog citizen portal.

The bug is the redirect_uri policy check. It is written as a prefix test
instead of an exact comparison, so a client may send any URI that *begins*
with the approved callback:

    https://portal.prithvi.example/callback
    https://portal.prithvi.example/callback.evil.example/steal   <- accepted

That is enough. The authorisation code is delivered to the attacker's host,
because the redirect is where the code lives. Everything after that -- the
code exchange, the access token, the citizen record -- is completely standard.

Written from scratch for this campaign. No existing vulnerable image is used and
no real service is referenced.
"""
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
CHAL_ID = os.environ.get("CHAL_ID", "WEB07")
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
        print("[WEB07] FLAG_SERVER_URL unset - offline, no flag issued",
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
        print("[WEB07] registered " + st["instance_id"], file=sys.stderr)
    except Exception as exc:
        print("[WEB07] registration failed: " + str(exc), file=sys.stderr)
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
        print("[WEB07] flag request failed: " + str(exc), file=sys.stderr)
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


def finish(st, ev, extra=None):
    """Shared completion path: claim the flag, persist it, return it."""
    st["objective_met"] = True
    flag = verify(st, ev)
    if not flag:
        # The solve stands even if the request failed; ask again rather than
        # making the player redo the redirect hijack.
        flag = claim_flag(st)
    if flag:
        st["flag"] = flag
        save_state(st)
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(OUTCOME, "w") as fh:
            fh.write(flag + "\n")
        print("[WEB07] OBJECTIVE MET " + st["instance_id"], flush=True)
    payload = {"objective": "complete", "flag": st.get("flag")}
    if extra:
        payload.update(extra)
    return payload


APPROVED_REDIRECT = "https://portal.prithvi.example/callback"
CODE_TTL = 600

# The signed-in resource owner. On the real portal this comes from the session
# cookie; here the consent screen always renders for this citizen.
CITIZEN = "CIT-8842019"
# The last-4 plus identifier this citizen's documents are filed under. Issued
# per instance by the flag server, so there is nothing to read in the handout.
CITIZEN_SECRET = ""


def set_objective(value):
    """This instance's protected value, issued by the flag server."""
    global CITIZEN_SECRET
    CITIZEN_SECRET = value

DB_FILE = os.path.join(STATE_DIR, "portal.db")


def db():
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    c = sqlite3.connect(DB_FILE)
    c.execute("""CREATE TABLE IF NOT EXISTS clients(
                    client_id TEXT PRIMARY KEY, name TEXT,
                    redirect_uri TEXT, created INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS codes(
                    code TEXT PRIMARY KEY, client_id TEXT, redirect_uri TEXT,
                    scope TEXT, subject TEXT, used INTEGER,
                    expires INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS tokens(
                    access_token TEXT PRIMARY KEY, client_id TEXT,
                    scope TEXT, subject TEXT, expires INTEGER)""")
    if c.execute("SELECT COUNT(*) FROM clients").fetchone()[0] == 0:
        c.execute(
            "INSERT INTO clients(client_id,name,redirect_uri,created) "
            "VALUES(?,?,?,?)",
            ("prithvi-web", "Prithvi Web",
             APPROVED_REDIRECT, int(time.time())))
        c.execute(
            "INSERT INTO clients(client_id,name,redirect_uri,created) "
            "VALUES(?,?,?,?)",
            ("field-survey", "Field Survey App",
             APPROVED_REDIRECT, int(time.time())))
    c.commit()
    return c


def redirect_allowed(uri):
    """RFC 6749 s3.1.2.3 requires exact string comparison of redirect URIs.

    RFC 8252 s7.3 additionally says the comparison MUST be exact -- a prefix
    or wildcard match lets an attacker who can influence any part of the URI
    capture codes intended for someone else.
    """
    # Looks like a prefix check. Is a prefix check.
    return uri.startswith(APPROVED_REDIRECT)


def new_code(c, client_id, redirect_uri, scope, subject):
    code = "ac_" + secrets.token_urlsafe(24)
    c.execute(
        "INSERT INTO codes(code,client_id,redirect_uri,scope,subject,used,"
        "expires) VALUES(?,?,?,?,?,0,?)",
        (code, client_id, redirect_uri, scope, subject,
         int(time.time()) + CODE_TTL))
    c.commit()
    return code


def page(title, body):
    return ("<!doctype html><meta charset=utf-8>"
            "<title>" + title + "</title>"
            "<body style=\"font-family:monospace;max-width:52em;margin:2em\">"
            "<h1>" + title + "</h1>" + body + "</body>")


def handle(cur, verb, u, q, body, H):
    if verb == "GET" and u.path == "/healthz":
        return H._json(200, {"ok": True, "service": "consent-screen"})

    if verb == "GET" and u.path == "/":
        c = db()
        rows = c.execute("SELECT client_id,name,redirect_uri FROM clients "
                         "ORDER BY created").fetchall()
        c.close()
        out = ["<p>Prithvi Udyog citizen portal. You are signed in as "
               "<b>" + CITIZEN + "</b>.</p>",
               "<h2>Registered clients</h2><table border=1 cellpadding=6>",
               "<tr><th>client_id<th>name<th>redirect_uri"]
        for cid, nm, ru in rows:
            out.append("<tr><td>" + cid + "<td>" + nm + "<td><code>" + ru +
                       "</code></tr>")
        out.append("</table>")
        out.append("<p><a href='/register'>register a client</a></p>")
        out.append("<h2>Org redirect policy</h2><p>Clients must use "
                   "<code>" + APPROVED_REDIRECT + "</code> exactly.</p>")
        return H._send(200, page("Consent Screen", "".join(out)))

    if u.path == "/register":
        if verb == "GET":
            return H._send(200, page("Register a client",
                "<form method=POST action='/register'>"
                "<p>name <input name=name value='Field Survey App'></p>"
                "<p>redirect_uri <input name=redirect_uri size=60 "
                "value='" + APPROVED_REDIRECT + "'></p>"
                "<p><input type=submit value=register></form>"))
        if verb == "POST":
            name = (body or {}).get("name", "client")
            uri = (body or {}).get("redirect_uri", "")
            if not redirect_allowed(uri):
                return H._json(400, {
                    "error": "redirect_uri_not_allowed",
                    "error_description": "must equal " + APPROVED_REDIRECT})
            cid = "client-" + secrets.token_hex(4)
            c = db()
            c.execute("INSERT INTO clients(client_id,name,redirect_uri,"
                      "created) VALUES(?,?,?,?)",
                      (cid, name, uri, int(time.time())))
            c.commit()
            c.close()
            return H._json(200, {"client_id": cid, "redirect_uri": uri})

    if u.path == "/authorize":
        if verb == "GET":
            cid = q.get("client_id", "")
            uri = q.get("redirect_uri", "")
            scope = q.get("scope", "profile")
            state = q.get("state", "")
            rt = q.get("response_type", "")
            c = db()
            row = c.execute("SELECT name FROM clients WHERE client_id=?",
                            (cid,)).fetchone()
            c.close()
            if not row:
                return H._json(400, {"error": "invalid_client"})
            if rt != "code":
                return H._json(400, {"error": "unsupported_response_type"})
            if not redirect_allowed(uri):
                return H._json(400, {"error": "invalid_redirect_uri"})
            return H._send(200, page("Authorisation request",
                "<p><b>" + row[0] + "</b> (" + cid + ") requests access to "
                "<b>" + scope + "</b>.</p>"
                "<p>It will be delivered to <code>" + uri + "</code>.</p>"
                "<form method=POST action='/authorize'>"
                "<input type=hidden name=client_id value='" + cid + "'>"
                "<input type=hidden name=redirect_uri value='" + uri + "'>"
                "<input type=hidden name=scope value='" + scope + "'>"
                "<input type=hidden name=state value='" + state + "'>"
                "<p><input type=submit name=decision value=allow> allow"
                "</p></form>"))
        if verb == "POST":
            cid = (body or {}).get("client_id", "")
            uri = (body or {}).get("redirect_uri", "")
            scope = (body or {}).get("scope", "profile")
            state = (body or {}).get("state", "")
            if not redirect_allowed(uri):
                return H._json(400, {"error": "invalid_redirect_uri"})
            c = db()
            code = new_code(c, cid, uri, scope, CITIZEN)
            c.close()
            sep = "&" if "?" in uri else "?"
            loc = uri + sep + urllib.parse.urlencode(
                {"code": code, "state": state})
            H.send_response(302)
            H.send_header("Location", loc)
            H.send_header("Content-Length", "0")
            H.end_headers()
            return True

    if verb == "POST" and u.path == "/token":
        code = (body or {}).get("code", "")
        cid = (body or {}).get("client_id", "")
        uri = (body or {}).get("redirect_uri", "")
        c = db()
        row = c.execute("SELECT client_id,redirect_uri,scope,subject,used,"
                        "expires FROM codes WHERE code=?",
                        (code,)).fetchone()
        if not row:
            c.close()
            return H._json(400, {"error": "invalid_grant",
                                 "error_description": "unknown code"})
        if row[4]:
            c.close()
            return H._json(400, {"error": "invalid_grant",
                                 "error_description": "code already used"})
        if row[5] < int(time.time()):
            c.close()
            return H._json(400, {"error": "invalid_grant",
                                 "error_description": "code expired"})
        if row[0] != cid:
            c.close()
            return H._json(400, {"error": "invalid_grant",
                                 "error_description": "client mismatch"})
        # RFC 6749 s4.1.3 -- the redirect_uri must match the one used in the
        # authorisation request, compared exactly.
        if row[1] != uri:
            c.close()
            return H._json(400, {"error": "invalid_grant",
                                 "error_description": "redirect_uri mismatch"})
        c.execute("UPDATE codes SET used=1 WHERE code=?", (code,))
        tok = "at_" + secrets.token_urlsafe(24)
        c.execute("INSERT INTO tokens(access_token,client_id,scope,subject,"
                  "expires) VALUES(?,?,?,?,?)",
                  (tok, cid, row[2], row[3], int(time.time()) + 3600))
        c.commit()
        c.close()
        return H._json(200, {"access_token": tok, "token_type": "Bearer",
                             "expires_in": 3600, "scope": row[2]})

    if verb == "GET" and u.path == "/api/profile":
        auth = H.headers.get("Authorization", "")
        tok = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
        c = db()
        row = c.execute("SELECT client_id,scope,subject,expires FROM tokens "
                        "WHERE access_token=?", (tok,)).fetchone()
        c.close()
        if not row or row[3] < int(time.time()):
            return H._json(401, {"error": "invalid_token"})
        if "profile" not in row[1].split():
            return H._json(403, {"error": "insufficient_scope",
                                 "scope": row[1]})
        out = {"sub": row[2], "name": "Lata Menon", "city": "Kochi",
               "account": "PRITHVI-UDYOG-4417", "status": "active"}
        if row[2] == CITIZEN:
            ev = {"victim_account": CITIZEN_SECRET}
            return H._json(200, dict(
                out, restricted={"recovery_contact": "+91-9847-112233",
                                 "aadhaar_last4": "4417"},
                **finish(cur, ev, {"scope": row[1],
                                      "client_id": row[0]})))
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
            print("[WEB07] " + self.address_string() + " " + (fmt % a),
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
    print("[WEB07] player service on :" + str(PLAYER_PORT), flush=True)
    print("[WEB07] flag server: " + (FLAG_SERVER or "(unset - offline)"),
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    serve()
