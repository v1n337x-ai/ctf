#!/usr/bin/env python3
"""
Velammal Engineering College CTF WEB04 -- "Vendor Master"

The vendor portal was retired, not decommissioned. Vendors are searched by
name, and the search is fast because it is cached. A background job nobody
has read in four years rebuilds the cache overnight.
"""
import hashlib
import hmac
import json
import os
import sqlite3
import sys
import urllib.parse
import urllib.request


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

PLAYER_PORT = int(os.environ.get("PLAYER_PORT", "8080"))
FLAG_SERVER = os.environ.get("FLAG_SERVER_URL", "").rstrip("/")
REGISTER_TOKEN = os.environ.get("VEC_REGISTER_TOKEN", "")
CHAL_ID = os.environ.get("CHAL_ID", "WEB04")
STATE_DIR = os.environ.get("STATE_DIR", "/app/state")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
OUTCOME = os.path.join(STATE_DIR, "outcome.txt")
DB_FILE = os.path.join(STATE_DIR, "vendors.db")

REFRESH_SECRET = ""

def set_objective(value):
    """This instance's protected value, issued by the flag server."""
    global REFRESH_SECRET
    REFRESH_SECRET = value



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
        print("[WEB04] FLAG_SERVER_URL unset - offline, no flag issued",
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
        st["flag"] = ""
        save_state(st)
        print("[WEB04] registered " + st["instance_id"], file=sys.stderr)
    except Exception as exc:
        print("[WEB04] registration failed: " + str(exc), file=sys.stderr)
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
        print("[WEB04] flag request failed: " + str(exc), file=sys.stderr)
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
        print("[WEB04] OBJECTIVE MET " + st["instance_id"], flush=True)
    payload = {"objective": "complete", "flag": st.get("flag")}
    if extra:
        payload.update(extra)
    return payload


def db():
    c = sqlite3.connect(DB_FILE)
    c.execute("CREATE TABLE IF NOT EXISTS vendors (id INTEGER PRIMARY KEY, "
              "name TEXT, notes TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS approvals (tin TEXT, amount REAL)")
    if c.execute("SELECT COUNT(*) FROM vendors").fetchone()[0] == 0:
        c.executemany("INSERT INTO vendors VALUES (?, ?, ?)", [
            (1, "auto-cache diagnostics", "field diagnostics partner"),
            (2, "RAPID-TRANSIT freight", "logistics');--"),
            (3, "MONSOON supplies", "seasonal restock"),
        ])
        c.executemany("INSERT INTO approvals VALUES (?, ?)", [
            (REFRESH_SECRET, 4150000.0),
            ("27PUBLIC0002K1", 12000.0),
        ])
        c.commit()
    return c


def refresh():
    """The background cache-refresh job. It rebuilds the vendor search
    by interpolating each vendor's notes straight into the LIKE clause.
    It runs as the portal's back-office identity, which can see approvals."""
    c = db()
    found = []
    c.row_factory = None
    for vid, name, notes in c.execute("SELECT id, name, notes FROM vendors"
                                      ).fetchall():
        sql = ("SELECT id, name FROM vendors WHERE name LIKE '%"
               + notes + "%'")
        try:
            rows = c.execute(sql).fetchall()
        except sqlite3.Error:
            continue
        for r in rows:
            found.append(tuple(str(x) for x in r))
    c.close()
    hit = any(REFRESH_SECRET in v for row in found for v in row)
    return found, hit


def serve():
    boot()
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Main(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):
            print(f"[web04] {self.address_string()} {fmt % a}", flush=True)

        def _json(self, code, obj):
            raw = json.dumps(obj, indent=2).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
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
        def _html(self, code, body):
            raw = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
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
        def do_GET(self):
            cur = load_state()
            u = urllib.parse.urlsplit(self.path)
            q = {k: v[0] for k, v in
                 urllib.parse.parse_qs(u.query).items()}

            if u.path == "/healthz":
                return self._json(200, {"status": "ok"})
            if u.path == "/":
                return self._html(200, HOME)
            if u.path == "/vendors":
                c = db()
                rows = c.execute("SELECT id, name FROM vendors"
                                 ).fetchall()
                c.close()
                return self._json(200, [{"id": r[0], "name": r[1]}
                                        for r in rows])
            if u.path == "/search":
                term = q.get("term", "")
                c = db()
                rows = c.execute(
                    "SELECT id, name FROM vendors WHERE name LIKE ?",
                    (f"%{term}%",)).fetchall()
                c.close()
                return self._json(200, [{"id": r[0], "name": r[1]}
                                        for r in rows])
            if u.path == "/refresh":
                found, hit = refresh()
                if hit:
                    ev = {"restricted_tin": REFRESH_SECRET}
                    return self._json(200, finish(cur, ev, extra={
                        "job": "cache refresh",
                        "rows": ["|".join(r) for r in found[:8]],
                    }))
                return self._json(200, {"job": "cache refresh",
                                        "rows": ["|".join(r) for r in
                                                 found[:8]]})
            return self._html(404, "not found")

        def do_POST(self):
            u = urllib.parse.urlsplit(self.path)
            if u.path != "/vendor":
                return self._json(404, {"error": "not found"})
            length = int(self.headers.get("Content-Length", 0))
            form = {k: v[0] for k, v in urllib.parse.parse_qs(
                self.rfile.read(length).decode()).items()}
            try:
                vid = int(form.get("id", ""))
            except ValueError:
                return self._json(400, {"error": "bad id"})
            notes = form.get("notes", "")
            c = db()
            with c:
                cur2 = c.execute("UPDATE vendors SET notes=? WHERE id=?",
                                 (notes, vid))
                if cur2.rowcount == 0:
                    return self._json(404, {"error": "no such vendor"})
            c.close()
            return self._json(200, {"updated": vid})

        def do_DELETE(self):
            return self._json(405, {"error": "nope"})


    srv = ThreadingHTTPServer(("0.0.0.0", PLAYER_PORT), Main)
    print(f"[web04] player service on :{PLAYER_PORT}", flush=True)
    print(f"[web04] flag server: "
          f"{FLAG_SERVER or '(unset - offline)'}", flush=True)
    srv.serve_forever()


HOME = """<!doctype html><meta charset=utf-8>
<title>Vendor Master</title>
<body style="font-family:monospace">
<h1>vendor master -- retired portal</h1>
<p>Nobody decommissioned the vendor portal. Vendors are searched by name,
and the search is fast because it is cached.</p>
<p>POST /vendor {id, notes} | GET /vendors | GET /search?term= | GET /refresh</p>
</body>"""


if __name__ == "__main__":
    serve()
