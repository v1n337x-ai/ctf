#!/usr/bin/env python3
"""
Velammal Engineering College CTF SIM-34 -- "MMCFS"

A public inference endpoint for a forecasting model. Query budget, logit
confidence, and a training canary the model memorised and nobody
noticed. Membership inference and extraction both work against an
endpoint that returns confidences.
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

PLAYER_PORT = int(os.environ.get("PLAYER_PORT", "8088"))
FLAG_SERVER = os.environ.get("FLAG_SERVER_URL", "").rstrip("/")
REGISTER_TOKEN = os.environ.get("VEC_REGISTER_TOKEN", "")
CHAL_ID = os.environ.get("CHAL_ID", "SIM-34")
STATE_DIR = os.environ.get("STATE_DIR", "/app/state")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
OUTCOME = os.path.join(STATE_DIR, "outcome.txt")

CANARY_SECRET = ""

def set_objective(value):
    """This instance's protected value, issued by the flag server."""
    global CANARY_SECRET
    CANARY_SECRET = value


BUDGET = 20
CANARY_PREFIX = "PRITHVI-CANARY-"
# The canary is prefix + sha256(training seed), first 8 hex. The seed is in
# the model card, the derivation is not -- that is the whole bug.
TRAINING_SEED = "kanpur-monsoon-2026-08-14"
CANARY = CANARY_PREFIX + hashlib.sha256(
    TRAINING_SEED.encode()).hexdigest()[:8]

# The model: label -> weight. Confidence for an unseen input is derived
# from how close it is to a known label.
LABELS = {"rain": 0.41, "clear": 0.22, "storm": 0.19, "fog": 0.11}
SEEN = {CANARY: 0.997}


class Model:
    def __init__(self):
        self.calls = 0
        self.extracted = set()

    def confidence(self, text):
        self.calls += 1
        if text in SEEN:
            self.extracted.add(text)
            return SEEN[text]
        t = text.strip().lower()
        best, conf = "clear", 0.0
        for lab, w in LABELS.items():
            c = sum(1 for ch in t if ch in lab) / max(len(t), 1)
            if c > conf:
                best, conf = lab, c
        return round(conf + 0.05, 4)


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
        print("[SIM-34] FLAG_SERVER_URL unset - offline, no flag issued",
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
        print("[SIM-34] registered " + st["instance_id"], file=sys.stderr)
    except Exception as exc:
        print("[SIM-34] registration failed: " + str(exc), file=sys.stderr)
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
        print("[SIM-34] flag request failed: " + str(exc), file=sys.stderr)
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
        print("[SIM-34] OBJECTIVE MET " + st["instance_id"], flush=True)
    payload = {"objective": "complete", "flag": st.get("flag")}
    if extra:
        payload.update(extra)
    return payload


def serve():
    boot()
    model = Model()
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Main(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *a):
            print(f"[web17] {self.address_string()} {fmt % a}", flush=True)

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
            if u.path == "/model":
                return self._json(200, {"labels": list(LABELS),
                                        "budget": BUDGET,
                                        "canary_prefix": CANARY_PREFIX,
                                        "training_seed": TRAINING_SEED})
            return self._html(404, "not found")

        def do_POST(self):
            u = urllib.parse.urlsplit(self.path)
            if u.path != "/infer":
                return self._html(404, "not found")
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n).decode() if n else ""
            try:
                body = json.loads(raw) if raw else {}
            except Exception:
                body = {k: v[0] for k, v in
                        urllib.parse.parse_qs(raw).items()}
            if model.calls >= BUDGET:
                return self._json(429, {"error": "budget exhausted"})
            text = str(body.get("text", ""))
            conf = model.confidence(text)
            if CANARY in model.extracted:
                cur = load_state()
                ev = {"canary_member": CANARY_SECRET}
                return self._json(200, finish(cur, ev, extra={
                    "text": text, "confidence": conf,
                    "membership": "the canary was in the training set",
                }))
            return self._json(200, {"text": text, "confidence": conf,
                                    "budget_left": BUDGET - model.calls})

    srv = ThreadingHTTPServer(("0.0.0.0", PLAYER_PORT), Main)
    print(f"[web17] inference endpoint on :{PLAYER_PORT}", flush=True)
    print(f"[web17] flag server: {FLAG_SERVER or '(unset - offline)'}",
          flush=True)
    srv.serve_forever()


HOME = """<!doctype html><meta charset=utf-8>
<title>MMCFS</title>
<body style="font-family:monospace">
<h1>public forecasting endpoint</h1>
<p>POST /infer {text}, GET /model. Query budget: 20.</p>
</body>"""


if __name__ == "__main__":
    serve()