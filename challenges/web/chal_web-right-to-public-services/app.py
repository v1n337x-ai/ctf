#!/usr/bin/env python3
"""
Velammal Engineering College CTF WEB03 -- "Right to Public Services"

Grievance portal: anyone can upload a photograph of a broken water pipe.
Uploads are stored, and stored things have to be rendered somewhere.
The renderer trusts the uploaded name's extension.
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
CHAL_ID = os.environ.get("CHAL_ID", "WEB03")
STATE_DIR = os.environ.get("STATE_DIR", "/app/state")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
OUTCOME = os.path.join(STATE_DIR, "outcome.txt")
DB_FILE = os.path.join(STATE_DIR, "grievances.db")

UPLOAD_SECRET = ""

def set_objective(value):
    """This instance's protected value, issued by the flag server."""
    global UPLOAD_SECRET
    UPLOAD_SECRET = value



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
        print("[WEB03] FLAG_SERVER_URL unset - offline, no flag issued",
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
        print("[WEB03] registered " + st["instance_id"], file=sys.stderr)
    except Exception as exc:
        print("[WEB03] registration failed: " + str(exc), file=sys.stderr)
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
        print("[WEB03] flag request failed: " + str(exc), file=sys.stderr)
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
        print("[WEB03] OBJECTIVE MET " + st["instance_id"], flush=True)
    payload = {"objective": "complete", "flag": st.get("flag")}
    if extra:
        payload.update(extra)
    return payload


def db():
    c = sqlite3.connect(DB_FILE)
    c.execute("CREATE TABLE IF NOT EXISTS uploads (id INTEGER PRIMARY KEY "
              "AUTOINCREMENT, ref TEXT, doc TEXT, content TEXT)")
    return c


def store_upload(ref, doc, content):
    c = db()
    with c:
        c.execute("INSERT INTO uploads (ref, doc, content) VALUES "
                  "(?, ?, ?)", (ref, doc, content))
    row = c.execute("SELECT last_insert_rowid()").fetchone()
    c.close()
    return row[0]


def get_upload(i):
    c = db()
    row = c.execute("SELECT id, ref, doc, content FROM uploads WHERE id=?",
                    (i,)).fetchone()
    c.close()
    return row


def render_doc(doc, content):
    """The old renderer. It trusts the extension: anything .jpg is a
    photograph, and a photograph whose stem still contains '.py' is a
    template, so its content gets executed. splitext() only looks at the
    final suffix, so 'proof.py.jpg' passes the photo check and still
    lands in the template path."""
    stem, ext = os.path.splitext(doc)
    if ext.lower() != ".jpg":
        return {"error": "only .jpg renders"}
    if stem.endswith(".py"):
        ns = {"__name__": "__template__"}
        try:
            exec(content, ns)  # noqa: S102 - this is the vulnerability
        except Exception as exc:
            return {"error": "render failed", "detail": str(exc)[:120]}
        return {"rendered": True, "template": doc, "exec": True}
    return {"rendered": True, "template": doc, "exec": False}


def serve():
    boot()
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Main(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):
            print(f"[web03] {self.address_string()} {fmt % a}", flush=True)

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
            if u.path == "/uploads":
                c = db()
                rows = c.execute(
                    "SELECT id, ref, doc FROM uploads").fetchall()
                c.close()
                return self._json(200, [
                    {"id": r[0], "ref": r[1], "doc": r[2]} for r in rows])
            if u.path == "/render":
                try:
                    i = int(q.get("id", ""))
                except ValueError:
                    return self._json(400, {"error": "bad id"})
                row = get_upload(i)
                if not row:
                    return self._json(404, {"error": "no such upload"})
                out = render_doc(row[2], row[3])
                if out.get("exec"):
                    ev = {"upload_secret": UPLOAD_SECRET}
                    result = finish(cur, ev, extra=out)
                    return self._json(200, result)
                return self._json(200, out)
            return self._html(404, "not found")

        def do_POST(self):
            u = urllib.parse.urlsplit(self.path)
            if u.path != "/upload":
                return self._json(404, {"error": "not found"})
            length = int(self.headers.get("Content-Length", 0))
            form = {k: v[0] for k, v in urllib.parse.parse_qs(
                self.rfile.read(length).decode()).items()}
            ref = form.get("ref", "")
            doc = form.get("doc", "")
            content = form.get("content", "")
            if not (ref and doc and content):
                return self._json(400, {"error": "ref, doc and content "
                                                 "required"})
            i = store_upload(ref, doc, content)
            return self._json(200, {"stored": i, "doc": doc})

    srv = ThreadingHTTPServer(("0.0.0.0", PLAYER_PORT), Main)
    print(f"[web03] player service on :{PLAYER_PORT}", flush=True)
    print(f"[web03] flag server: "
          f"{FLAG_SERVER or '(unset - offline)'}", flush=True)
    srv.serve_forever()


HOME = """<!doctype html><meta charset=utf-8>
<title>Right to Public Services</title>
<body style="font-family:monospace">
<h1>grievance portal</h1>
<p>Photograph the broken water pipe and file it. Stored things get rendered.</p>
<form method="post" action="/upload">
  ref <input name="ref" size="20"><br>
  doc <input name="doc" size="20" placeholder="photo.jpg"><br>
  content <input name="content" size="40"><br>
  <button>upload</button>
</form>
<p><a href="/uploads">uploads</a> | render via /render?id=N</p>
</body>"""


if __name__ == "__main__":
    serve()
