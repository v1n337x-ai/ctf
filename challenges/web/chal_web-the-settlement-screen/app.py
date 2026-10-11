#!/usr/bin/env python3
"""
Velammal Engineering College CTF WEB08 -- "The Settlement Screen"

First-order UNION-selectable SQL injection in the counterparty search, against
an old vendor settlement component that was never replaced.

The search box interpolates the operator's term straight into the statement.
There is no stacked query and no privilege boundary to cross -- a single
UNION SELECT against a table the application can see is enough.

Written from scratch for this campaign. No existing vulnerable image is used and
no real service is referenced.
"""
import hashlib
import hmac
import json
import os
import sqlite3
import sys
import urllib.parse
import urllib.request

PLAYER_PORT = int(os.environ.get("PLAYER_PORT", "8080"))
FLAG_SERVER = os.environ.get("FLAG_SERVER_URL", "").rstrip("/")
# Bootstrap credential for the flag server's register endpoint. Injected
# at RUN time; never baked into an image layer.
REGISTER_TOKEN = os.environ.get("VEC_REGISTER_TOKEN", "")
CHAL_ID = os.environ.get("CHAL_ID", "WEB08")
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
        print("[WEB08] FLAG_SERVER_URL unset - offline, no flag issued",
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
        # This instance's protected settlement row, issued per instance. It is
        # written into the ledger below; the settlement screen is the only way
        # to read it back out.
        if d.get("objective_value"):
            set_objective(d["objective_value"])
            st["objective_value"] = d["objective_value"]
        # The flag server deliberately does NOT return the flag here. It is
        # released only by /api/v1/complete once this instance proves it met
        # the objective with a valid HMAC. Nothing is cached at boot.
        st["flag"] = ""
        save_state(st)
        print("[WEB08] registered " + st["instance_id"], file=sys.stderr)
    except Exception as exc:
        print("[WEB08] registration failed: " + str(exc), file=sys.stderr)
    return st


def sign(st, proof):
    key = bytes.fromhex(st.get("challenge_secret", ""))
    msg = ("%s.%s.%s" % (CHAL_ID, st["instance_id"], proof)).encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def evidence_digest(evidence):
    return hashlib.sha256(json.dumps(evidence, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def verify(st, evidence):
    """Submit what the challenge disclosed and ask the server to decide.

    The server runs the verifier and only releases the flag if the evidence
    matches the value it issued to this instance. Nothing here decides that.
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
        print("[WEB08] flag request failed: " + str(exc), file=sys.stderr)
        return None


def claim_flag(st):
    """Re-fetch a flag already earned for this instance.

    Verification belongs to the instance, not to the request, so if the tunnel
    dropped while the flag was in flight the player can simply ask again
    instead of losing the solve.
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
        # The solve stands even if the request failed; ask again on the next
        # page load rather than making the player redo the exploit.
        flag = claim_flag(st)
    if flag:
        st["flag"] = flag
        save_state(st)
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(OUTCOME, "w") as fh:
            fh.write(flag + "\n")
        print("[WEB08] OBJECTIVE MET " + st["instance_id"], flush=True)
    payload = {"objective": "complete", "flag": st.get("flag")}
    if extra:
        payload.update(extra)
    return payload


DB_FILE = os.path.join(STATE_DIR, "settlement.db")

# The component version string the ops team never got round to upgrading.
COMPONENT = "SettleKit 2.4.1"

# The protected settlement row. Both values are issued per instance by the
# flag server at registration and written in by set_objective() at boot. There
# is deliberately nothing readable here: the whole point is that the only way
# to learn this row is to make the settlement screen disclose it.
SECRET_TIN = ""
SECRET_REF = ""


def set_objective(value):
    """Take this instance's protected values from the flag server."""
    global SECRET_TIN, SECRET_REF
    SECRET_REF = value
    SECRET_TIN = "31" + hashlib.sha256(value.encode()).hexdigest()[:12].upper()


def db():
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    c = sqlite3.connect(DB_FILE)
    c.execute("""CREATE TABLE IF NOT EXISTS counterparties(
                    id INTEGER PRIMARY KEY, name TEXT, tin TEXT,
                    bank TEXT, status TEXT)""")
    if c.execute("SELECT COUNT(*) FROM counterparties").fetchone()[0] == 0:
        c.executemany(
            "INSERT INTO counterparties(name,tin,bank,status) "
            "VALUES(?,?,?,?)",
            [("Kavitha Ranganathan", "27AAVFK8821M1Z9", "PRITHVI COOP",
              "verified"),
             ("Ananya Bhattacharya", "29ABCDE1234F1Z2", "PRITHVI COOP",
              "verified"),
             ("Sudha Iyer", "30ZZZZ9999Y1X3", "SEVA PAY", "pending")])
        # Internal settlement ledger. Not exposed by any documented screen.
        c.execute("""CREATE TABLE IF NOT EXISTS settlements(
                        id INTEGER PRIMARY KEY, tin TEXT, ref TEXT,
                        amount REAL, state TEXT)""")
        c.execute("INSERT INTO settlements(tin,ref,amount,state) "
                  "VALUES(?,?,?,?)",
                  (SECRET_TIN, SECRET_REF, 4150000.0, "reserved"))
    c.commit()
    return c


def page(title, body):
    return ("<!doctype html><meta charset=utf-8>"
            "<title>" + title + "</title>"
            "<body style=\"font-family:monospace;max-width:56em;margin:2em\">"
            "<h1>" + title + "</h1>" + body + "</body>")


def handle(cur, verb, u, q, body, H):
    if verb == "GET" and u.path == "/healthz":
        return H._json(200, {"ok": True, "service": "settlement-screen"})

    if verb == "GET" and u.path == "/":
        return H._send(200, page("Settlement Screen",
            "<p>Counterparty settlement console. Settlement component: <code>"
            + COMPONENT + "</code> (vendor support ends 2023).</p>"
            "<form method=GET action='/search'>"
            "<p>find counterparty <input name=q size=40 "
            "value='Kavitha'></p>"
            "<p><input type=submit value=search></p></form>"
            "<p>Documents: <a href='/api/v1/settlement'>"
            "/api/v1/settlement</a></p>"))

    if u.path == "/search":
        term = q.get("q", "")
        c = db()
        # The counterparty search. SettleKit 2.4.1 builds this statement by
        # string concatenation; it was reported in 2023 and never patched.
        try:
            cs = c.execute(
                "SELECT id, name, tin, bank FROM counterparties "
                f"WHERE name LIKE '%{term}%' ORDER BY id")
            rows = cs.fetchall()
            err = None
        except Exception as exc:
            rows, err = [], str(exc)
        c.close()
        out = ["<p>results for <b>" + term + "</b></p>",
               "<table border=1 cellpadding=6><tr><th>name<th>tin<th>bank"]
        for r in rows:
            out.append("<tr><td>" + str(r[1]) + "<td>" + str(r[2]) + "<td>"
                       + str(r[3]) + "</tr>")
        out.append("</table>")
        if err:
            out.append("<p class=e>" + err + "</p>")
        # A hit on the internal ledger is the objective. Which column the solver
        # projects the tin and the reference into is their choice, so look for
        # both values anywhere in the row rather than assuming positions.
        for r in rows:
            cells = [str(x) for x in r]
            if SECRET_TIN in cells:
                ev = {"settlement_ref": next((c for c in cells
                                              if c == SECRET_REF), ""),
                      "settlement_tin": SECRET_TIN}
                shown = next((c for c in cells if c == SECRET_REF), SECRET_TIN)
                return H._send(200, page("Settlement Screen",
                    "".join(out) + finish_html(cur, ev, shown)))
        return H._send(200, page("Settlement Screen", "".join(out)))

    if verb == "GET" and u.path == "/api/v1/settlement":
        c = db()
        n = c.execute("SELECT COUNT(*) FROM settlements").fetchone()[0]
        c.close()
        return H._json(200, {"component": COMPONENT, "ledger_rows": n,
                             "note": "ledger contents are not exposed"})

    return None


def finish_html(cur, evidence, row):
    st = finish(cur, evidence)
    return ("<h2>objective complete</h2><p>An internal settlement row was "
            "disclosed through the counterparty search.</p><pre>"
            + row + "</pre><h2>flag</h2><pre style=\"font-size:1.3em;"
            "background:#161b22;padding:1em\">" + st.get("flag", "")
            + "</pre>")

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
            print("[WEB08] " + self.address_string() + " " + (fmt % a),
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
    print("[WEB08] player service on :" + str(PLAYER_PORT), flush=True)
    print("[WEB08] flag server: " + (FLAG_SERVER or "(unset - offline)"),
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    serve()
