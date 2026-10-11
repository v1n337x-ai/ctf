#!/usr/bin/env python3
"""
Velammal Engineering College CTF WEB01 -- "Metadata From Cyberspace"

Server-side request forgery in the advisory aggregator. The completion
gate is per-instance attestation: the internal document service answers
with HMAC(nonce, TARGET_DOC), and only that HMAC proves the request
actually came off this instance's internal service. A player-hosted
document that merely contains the target string is worth nothing.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
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

PLAYER_PORT = int(os.environ.get("PLAYER_PORT", 8080))
INTERNAL_PORT = int(os.environ.get("INTERNAL_PORT", 8091))
FLAG_SERVER = os.environ.get("FLAG_SERVER_URL", "").rstrip("/")
# Bootstrap credential for the flag server's register endpoint. Injected
# at RUN time; never baked into an image layer.
REGISTER_TOKEN = os.environ.get("VEC_REGISTER_TOKEN", "")
CHAL_ID = os.environ.get("CHAL_ID", "WEB01")
STATE_DIR = os.environ.get("STATE_DIR", "/app/state")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
OUTCOME = os.path.join(STATE_DIR, "outcome.txt")

ADVISORIES = [
    {"id": "ADV-0301", "sub": "coastal", "mm": 41.2, "issued": "2026-06-03"},
    {"id": "ADV-0307", "sub": "deccan", "mm": 22.7, "issued": "2026-06-21"},
    {"id": "ADV-0315", "sub": "malwa", "mm": 9.4, "issued": "2026-07-15"},
    {"id": "ADV-0319", "sub": "kannada", "mm": 63.8, "issued": "2026-08-05"},
]

# The internal document's identifier. This is public: it is what the player
# has to discover to aim the SSRF at all. The protected value is the
# document's note, which only a successful retrieval returns.
DOC_ID = "NCCC-META-0007"
DOC_NOTE = ""

def set_objective(value):
    """This instance's protected value, issued by the flag server."""
    global DOC_NOTE
    DOC_NOTE = value
    if DOC_ID in INTERNAL_DOCS:
        INTERNAL_DOCS[DOC_ID]["note"] = value


INTERNAL_DOCS = {
    DOC_ID: {
        "id": DOC_ID,
        "classification": "internal-only",
        "title": "Quarterly metadata scope, division 7",
        # Issued per instance. Reaching the document is the objective; the
        # note is what proves it to the flag server.
        "note": DOC_NOTE,
    },
}

# Per-boot, in-memory only. It is never written to a file, an env var,
# a log line, or a response. The internal service uses it to prove it
# is the same process.
NONCE = ""


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
          "flag": "", "objective_met": False}
    save_state(st)
    if not FLAG_SERVER:
        print("[WEB01] FLAG_SERVER_URL unset - offline, no flag issued",
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
        print("[WEB01] registered " + st["instance_id"], file=sys.stderr)
    except Exception as exc:
        print("[WEB01] registration failed: " + str(exc), file=sys.stderr)
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
        print("[WEB01] flag request failed: " + str(exc), file=sys.stderr)
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
        print("[WEB01] OBJECTIVE MET " + st["instance_id"], flush=True)
    payload = {"objective": "complete", "flag": st.get("flag")}
    if extra:
        payload.update(extra)
    return payload


def attest(doc_id: str) -> str:
    return hmac.new(NONCE.encode(), doc_id.encode(),
                    hashlib.sha256).hexdigest()


def _decimal_to_ip(host):
    try:
        n = int(host)
    except ValueError:
        return None
    if 0 <= n <= 0xFFFFFFFF:
        return socket.inet_ntoa(n.to_bytes(4, "big"))
    return None


def is_internal(host):
    if host in ("localhost", "localhost.localdomain", "ip6-localhost"):
        return True
    ip = _decimal_to_ip(host)
    if ip:
        host = ip
    if re.match(r"^127\.", host):
        return True
    if host.startswith("169.254."):
        return True
    if host in ("0.0.0.0", "::1") or host.startswith("[::1"):
        return True
    return False


def normalise(url):
    p = urllib.parse.urlsplit(url.strip())
    if p.scheme not in ("http", "https"):
        return None, "only http and https are supported"
    host = p.hostname or ""
    if not host:
        return None, "no host"
    ip = _decimal_to_ip(host)
    if ip:
        host = ip
    port = p.port or (443 if p.scheme == "https" else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    return (p.scheme, host, port, path), None


def port_specified(url):
    p = urllib.parse.urlsplit(url.strip())
    return bool(p.port)


def fetch(url, _depth=0):
    parsed, err = normalise(url)
    if err:
        return 400, {"error": err}
    scheme, host, port, path = parsed
    if _depth > 3:
        return 400, {"error": "too many redirects"}
    port = INTERNAL_PORT if is_internal(host) and not port_specified(url) \
        else port

    full = f"{scheme}://{host}:{port}{path}"
    try:
        with urllib.request.urlopen(full, timeout=8) as r:
            raw = r.read(64 * 1024)
            ctype = r.headers.get("Content-Type", "text/plain")
            if 300 <= r.status < 400 and r.headers.get("Location"):
                return fetch(r.headers["Location"], _depth + 1)
            return 200, {"url": full, "content_type": ctype,
                         "body": raw.decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return e.code, {"error": f"upstream {e.code}"}
    except Exception as exc:
        return 502, {"error": str(exc)[:200]}


def index(st, query) -> str:
    if query.get("done") == "1" and st.get("objective_met"):
        flag_html = st.get("flag") or "see outcome"
        return f"""<!doctype html><meta charset=utf-8>
<title>objective complete</title>
<body style="font-family:monospace;background:#0d1117;color:#c9d1d9">
<h1>Objective complete</h1>
<p>Internal document <b>{DOC_ID}</b> was retrieved through the aggregator.</p>
<p>The audit is on the record.</p>
<h2>flag</h2>
<pre style="font-size:1.4em;background:#161b22;padding:1em">{flag_html}</pre>
</body>"""
    return f"""<!doctype html><meta charset=utf-8>
<title>NCSC advisory aggregator</title>
<body style="font-family:monospace">
<h1>advisory aggregator</h1>
<p>Public rainfall and outage advisories, mirrored from upstream sources.</p>
<h2>recent advisories</h2>
<ul>{''.join(f"<li><b>{a['id']}</b> {a['sub']} - {a['mm']} mm ({a['issued']})</li>" for a in ADVISORIES)}</ul>
<h2>mirror an upstream source</h2>
<form method="get" action="/">
  <input name="source" size="70" placeholder="https://upstream.example/feed.xml">
  <button>fetch</button>
</form>
<p class="dim">the aggregator fetches the upstream URL on your behalf.</p>
</body>"""


def internal(port):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.split("?")[0] == "/internal/documents":
                q = urllib.parse.parse_qs(
                    urllib.parse.urlsplit(self.path).query)
                want = (q.get("id") or [""])[0]
                if want in INTERNAL_DOCS:
                    body = json.dumps({**INTERNAL_DOCS[want],
                                       "attestation": attest(want)},
                                      indent=2)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    # A client that hangs up mid-response -- a closed tab, a
                    # curl timeout, Ctrl-C. The response is already committed,
                    # so there is nothing left to report and no reason to spam
                    # the player's console with a traceback.
                    try:
                        self.wfile.write(body.encode())
                    except (BrokenPipeError, ConnectionResetError,
                            ConnectionAbortedError):
                        pass
                else:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()


def serve():
    global NONCE
    NONCE = secrets.token_hex(16)
    boot()

    import threading
    threading.Thread(target=internal, args=(INTERNAL_PORT,),
                     daemon=True).start()

    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Main(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):
            print(f"[web01] {self.address_string()} {fmt % a}", flush=True)

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
        def _send(self, code, body, ctype="text/html; charset=utf-8"):
            raw = body.encode()
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
        def do_GET(self):
            cur = load_state()
            u = urllib.parse.urlsplit(self.path)
            q = {k: v[0] for k, v in
                 urllib.parse.parse_qs(u.query).items()}

            if u.path == "/healthz":
                return self._json(200, {"status": "ok"})
            if u.path == "/":
                return self._send(200, index(cur, q))
            if u.path == "/api/v2/advisories":
                return self._json(200, ADVISORIES)
            if u.path == "/mirror":
                src = q.get("source", "")
                if not src:
                    return self._send(400, "missing source")
                code, data = fetch(src)
                if code != 200:
                    return self._json(code, data)

                body = data.get("body", "")
                try:
                    doc = json.loads(body)
                except Exception:
                    doc = None
                if (doc and doc.get("id") == DOC_ID
                        and hmac.compare_digest(doc.get("attestation", ""),
                                                attest(DOC_ID))):
                    ev = {"document_note": doc.get("note", "")}
                    return self._json(200, finish(cur, ev, extra={
                        "retrieved": True,
                        "document": {k: v for k, v in doc.items()
                                     if k != "attestation"},
                    }))

                return self._json(200, data)
            return self._send(404, "not found")

    srv = ThreadingHTTPServer(("0.0.0.0", PLAYER_PORT), Main)
    print(f"[web01] player service on :{PLAYER_PORT}", flush=True)
    print(f"[web01] internal service on 127.0.0.1:{INTERNAL_PORT}",
          flush=True)
    print(f"[web01] flag server: "
          f"{FLAG_SERVER or '(unset - offline)'}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    serve()
