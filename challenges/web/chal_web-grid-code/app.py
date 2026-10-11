#!/usr/bin/env python3
"""
Velammal Engineering College CTF WEB05 -- "Grid Code"

A utility GraphQL gateway. Introspection is on, and it is *not* the
vulnerability -- it is how you find the vulnerable field. One resolver
reads a legacy ledger that crosses a tenant boundary, and it never asks
whose record was requested.
"""
import hashlib
import hmac
import json
import os
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
CHAL_ID = os.environ.get("CHAL_ID", "WEB05")
STATE_DIR = os.environ.get("STATE_DIR", "/app/state")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
OUTCOME = os.path.join(STATE_DIR, "outcome.txt")

LEDGER_SECRET = ""

def set_objective(value):
    """This instance's protected value, issued by the flag server."""
    global LEDGER_SECRET
    LEDGER_SECRET = value


MY_TENANT = "GRID-NORTH"
OTHER_TENANT = "GRID-SOUTH"

SCHEMA = """\
type Query {
  operator(id: ID): Operator
  myTenant: String
  legacyAssetLedger: LegacyLedger
  __schema: Schema
}
type Operator { id: ID, name: String }
type LegacyLedger { id: ID, tenant: String, valvePosition: String }
"""


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
        print("[WEB05] FLAG_SERVER_URL unset - offline, no flag issued",
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
        print("[WEB05] registered " + st["instance_id"], file=sys.stderr)
    except Exception as exc:
        print("[WEB05] registration failed: " + str(exc), file=sys.stderr)
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
        print("[WEB05] flag request failed: " + str(exc), file=sys.stderr)
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
        print("[WEB05] OBJECTIVE MET " + st["instance_id"], flush=True)
    payload = {"objective": "complete", "flag": st.get("flag")}
    if extra:
        payload.update(extra)
    return payload


def answer(query: str, cur):
    """A deliberately small GraphQL answerer: find the requested top-level
    fields and resolve each one. `legacyAssetLedger` is the broken one."""
    fields = []
    depth = query.count("{")
    head = query.split("{", 1)[1] if "{" in query else query
    for name in ("operator", "myTenant", "legacyAssetLedger", "__schema"):
        if name in query:
            fields.append(name)
    data = {}
    if "__schema" in fields:
        data["__schema"] = {"description": SCHEMA}
    if "operator" in fields:
        data["operator"] = {"id": "OP-7", "name": "North dispatch"}
    if "myTenant" in fields:
        data["myTenant"] = MY_TENANT
    if "legacyAssetLedger" in fields:
        # The resolver that forgot the tenant check.
        row = {"id": "LEDGER-4417", "tenant": OTHER_TENANT,
               "valvePosition": "OPEN-12%"}
        ev = {"cross_tenant_record": LEDGER_SECRET}
        data["legacyAssetLedger"] = row
        return data, ev
    return data, None


def serve():
    boot()
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Main(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):
            print(f"[web05] {self.address_string()} {fmt % a}", flush=True)

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
            u = urllib.parse.urlsplit(self.path)
            if u.path == "/healthz":
                return self._json(200, {"status": "ok"})
            if u.path == "/":
                return self._html(200, HOME)
            return self._html(404, "not found")

        def do_POST(self):
            u = urllib.parse.urlsplit(self.path)
            if u.path != "/graphql":
                return self._json(404, {"error": "not found"})
            cur = load_state()
            try:
                n = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(n).decode()
            except Exception:
                return self._json(400, {"error": "bad body"})
            query = ""
            try:
                query = json.loads(raw).get("query", "")
            except Exception:
                form = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
                query = form.get("query", "")
            if not query:
                return self._json(400, {"error": "query required"})
            data, ev = answer(query, cur)
            if ev is not None:
                out = finish(cur, ev, extra={"data": data})
                return self._json(200, out)
            return self._json(200, {"data": data})

    srv = ThreadingHTTPServer(("0.0.0.0", PLAYER_PORT), Main)
    print(f"[web05] player service on :{PLAYER_PORT}", flush=True)
    print(f"[web05] flag server: {FLAG_SERVER or '(unset - offline)'}",
          flush=True)
    srv.serve_forever()


HOME = """<!doctype html><meta charset=utf-8>
<title>Grid Code</title>
<body style="font-family:monospace">
<h1>grid dispatch gateway</h1>
<p>GraphQL at /graphql. Introspection is enabled.</p>
<pre>POST /graphql {"query": "{ myTenant }"}</pre>
</body>"""


if __name__ == "__main__":
    serve()
