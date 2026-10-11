#!/usr/bin/env python3
"""
Velammal Engineering College CTF WEB10 -- "The Build Server"

An in-house CI controller standing in for Jenkins. The pipeline is the whole
story:

    pipeline agent any
    stages {
        stage('firmware') {
            steps {
                sh 'echo "building rev $REV" && cp -r ../../src/firmware ./out'
            }
        }
    }

Two findings, and the player needs both.

  1. The build step interpolates REV into a single-quoted shell string, so the
     parameter is a command, not an argument.
  2. The agent is "any", so the workspace sits directly under the controller
     home. ../../secrets/credentials.xml is simply a path away.

The credential in that file is obfuscated the way Jenkins obfuscates a
Secret -- base64, a two-byte length prefix, and an XOR against a fixed
constant. It is obfuscation, not encryption, and it is reversible by design.
A player who reads the file is expected to undo it.

Written from scratch for this campaign. No Jenkins installation, plugin or
image is used and no real controller is referenced.
"""
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request

PLAYER_PORT = int(os.environ.get("PLAYER_PORT", "8080"))
FLAG_SERVER = os.environ.get("FLAG_SERVER_URL", "").rstrip("/")
# Bootstrap credential for the flag server's register endpoint. Injected
# at RUN time; never baked into an image layer.
REGISTER_TOKEN = os.environ.get("VEC_REGISTER_TOKEN", "")
CHAL_ID = os.environ.get("CHAL_ID", "WEB10")
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
        print("[WEB10] FLAG_SERVER_URL unset - offline, no flag issued",
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
        print("[WEB10] registered " + st["instance_id"], file=sys.stderr)
    except Exception as exc:
        print("[WEB10] registration failed: " + str(exc), file=sys.stderr)
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
        print("[WEB10] flag request failed: " + str(exc), file=sys.stderr)
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
        print("[WEB10] OBJECTIVE MET " + st["instance_id"], flush=True)
    payload = {"objective": "complete", "flag": st.get("flag")}
    if extra:
        payload.update(extra)
    return payload


JENKINS_VERSION = "2.289.1"
MAGIC = b":::::"                      # hudson.util.Secret's fixed mask
# The controller runs unprivileged, so its home lives under the writable
# state dir. The layout is what matters: <home>/workspace/<job> with
# <home>/secrets one level above it.
HOME = os.environ.get("JENKINS_HOME",
                     os.path.join(STATE_DIR, "jenkins"))
WORKSPACE = os.path.join(HOME, "workspace", "firmware")
SECRETS = os.path.join(HOME, "secrets")
CREDS = os.path.join(SECRETS, "credentials.xml")
LOG = os.path.join(HOME, "build.log")
KEY_FILE = os.path.join(HOME, "signing.key")

CRED_ID = "prithvi-firmware-signing"


def secret_encrypt(plain):
    """Jenkins-style Secret obfuscation: len prefix, XOR, base64."""
    b = plain.encode()
    out = bytearray([len(b) & 0xFF, (len(b) >> 8) & 0xFF])
    for i, ch in enumerate(b):
        out.append(ch ^ MAGIC[i % len(MAGIC)])
    return base64.b64encode(bytes(out)).decode()


def signing_key():
    """This instance's build signing credential.

    Issued by the flag server at registration, so it is not in the handout.
    Offline there is nothing to verify against and no flag can be issued.
    """
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE) as fh:
            return fh.read().strip()
    issued = load_state().get("objective_value") or ""
    value = issued or ("FW-" + os.urandom(14).hex())
    os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
    with open(KEY_FILE, "w") as fh:
        fh.write(value)
    return value


def provision():
    """Lay out the controller home the way a fresh install would."""
    for d in (WORKSPACE, SECRETS, os.path.join(HOME, "src", "firmware")):
        os.makedirs(d, exist_ok=True)
    with open(os.path.join(WORKSPACE, "build.sh"), "w") as fh:
        fh.write("# pipeline workspace\n")
    signing_key()          # ensure it exists before credentials.xml is written
    if not os.path.exists(CREDS):
        blob = secret_encrypt(signing_key())
        with open(CREDS, "w") as fh:
            fh.write(
                "<?xml version='1.1' encoding='UTF-8'?>\n"
                "<com.cloudbees.plugins.credentials.impl."
                "SystemCredentialsProvider>\n"
                "  <id>" + CRED_ID + "</id>\n"
                "  <description>prithvi firmware signing key</description>\n"
                "  <secret>{" + blob + "}</secret>\n"
                "</com.cloudbees.plugins.credentials.impl."
                "SystemCredentialsProvider>\n")
    if not os.path.exists(LOG):
        open(LOG, "w").close()


def last_log():
    try:
        with open(LOG) as fh:
            return fh.read()
    except Exception:
        return ""


def page(title, body):
    return ("<!doctype html><meta charset=utf-8><title>" + title + "</title>"
            "<body style=\"font-family:monospace;max-width:58em;margin:2em\">"
            "<h1>" + title + "</h1>" + body + "</body>")


def handle(cur, verb, u, q, body, H):
    if verb == "GET" and u.path == "/healthz":
        return H._json(200, {"ok": True, "service": "build-controller"})

    if verb == "GET" and u.path == "/":
        return H._send(200, page("Build Controller",
            "<p>Jenkins ver <code>" + JENKINS_VERSION + "</code></p>"
            "<p><a href='/job/firmware'>job: firmware</a></p>"))

    if verb == "GET" and u.path == "/job/firmware":
        return H._send(200, page("firmware [Jenkins]",
            "<p>Parameterized build. <code>agent any</code>.</p>"
            "<pre>sh 'echo \"building rev $REV\" "
            "&& cp -r ../../src/firmware ./out'</pre>"
            "<form method=POST action='/job/firmware/build'>"
            "<p>REV <input name=REV size=44 value='114'></p>"
            "<p><input type=submit value='Build Now'></p></form>"
            "<p><a href='/console'>console output</a></p>"
            "<h3>verify a signing key</h3>"
            "<form method=POST action='/job/firmware/verify'>"
            "<p>key <input name=key size=44></p>"
            "<p><input type=submit value=verify></p></form>"))

    if verb == "POST" and u.path == "/job/firmware/build":
        rev = (body or {}).get("REV", "1")
        # The Jenkins Groovy interpolation happens before the shell sees the
        # string, so $REV lands inside single quotes unescaped.
        cmd = ('echo "building rev ' + rev + '" '
               '&& cp -r ../../src/firmware ./out')
        try:
            p = subprocess.run(["/bin/sh", "-c", cmd], cwd=WORKSPACE,
                               capture_output=True, timeout=30)
            out = (p.stdout + p.stderr).decode("utf-8", "replace")
        except Exception as exc:
            out = "build agent unavailable: " + str(exc)
        with open(LOG, "w") as fh:
            fh.write(out)
        return H._send(200, page("firmware [Jenkins] #1",
            "<pre>" + out.replace("&", "&amp;").replace("<", "&lt;")
            + "</pre><p><a href='/console'>console output</a></p>"))

    if verb == "GET" and u.path == "/console":
        return H._send(200, page("Console Output",
            "<pre>" + last_log().replace("&", "&amp;").replace("<", "&lt;")
            + "</pre>"))

    if verb == "POST" and u.path == "/job/firmware/verify":
        key = (body or {}).get("key", "").strip()
        if key and key == signing_key():
            # The credential the over-trusted agent signed with. It is
            # generated per instance at boot, so it is not in the handout.
            ev = {"signing_credential": key}
            return H._json(200, dict(
                {"verified": True, "credential": CRED_ID},
                **finish(cur, ev)))
        return H._json(400, {"verified": False,
                             "error": "key does not match any credential"})

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
    provision()
    cur = load_state()

    class Main(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):
            print("[WEB10] " + self.address_string() + " " + (fmt % a),
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
    print("[WEB10] player service on :" + str(PLAYER_PORT), flush=True)
    print("[WEB10] flag server: " + (FLAG_SERVER or "(unset - offline)"),
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    serve()
