#!/usr/bin/env python3
"""
Velammal Engineering College CTF SIM-30 -- "Cross Domain"

The design enclave is called air-gapped in the presentations, which is
not entirely true. It is connected by an update conduit, because
software has to be updated somehow. The agent checks the version. It
does not check the trust.
"""
import hashlib
import hmac
import json
import os
import socket
import socketserver
import sys
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

PLAYER_PORT = int(os.environ.get("PLAYER_PORT", "2225"))
FLAG_SERVER = os.environ.get("FLAG_SERVER_URL", "").rstrip("/")
REGISTER_TOKEN = os.environ.get("VEC_REGISTER_TOKEN", "")
CHAL_ID = os.environ.get("CHAL_ID", "SIM-30")
STATE_DIR = os.environ.get("STATE_DIR", "/app/state")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
OUTCOME = os.path.join(STATE_DIR, "outcome.txt")

ENCLAVE_SECRET = ""

def set_objective(value):
    """This instance's protected value, issued by the flag server."""
    global ENCLAVE_SECRET
    ENCLAVE_SECRET = value


AGENT_VERSION = "4.11.1"
SIGNED = {"4.11.0": True, "4.11.1": True}      # only these are signed


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
        print("[SIM-30] FLAG_SERVER_URL unset - offline, no flag issued",
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
        print("[SIM-30] registered " + st["instance_id"], file=sys.stderr)
    except Exception as exc:
        print("[SIM-30] registration failed: " + str(exc), file=sys.stderr)
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
        print("[SIM-30] flag request failed: " + str(exc), file=sys.stderr)
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
        print("[SIM-30] OBJECTIVE MET " + st["instance_id"], flush=True)
    payload = {"objective": "complete", "flag": st.get("flag")}
    if extra:
        payload.update(extra)
    return payload


def run(state, line):
    if line == "whoami":
        return "eng\\\\plant\\n$ "
    if line == "help":
        return "    whoami | agent --version | push | plant | enclave-shell\n$ "
    if line == "agent --version":
        return f"update-agent {AGENT_VERSION}\n$ "
    if line.startswith("push "):
        _, version, payload = line.split(" ", 2)
        version = version.strip()
        # the only check is the version string. Nothing verifies the signer.
        state["staged"] = (version, payload.strip())
        return (f"pushed {version} to the conduit queue "
                f"(agent did not ask who signed it)\n$ ")
    if line == "plant":
        if not state.get("staged"):
            return "nothing staged\n$ "
        state["planted"] = True
        return ("persistence hook installed in the enclave "
                "(keystroke-log)\n$ ")
    if line == "enclave-shell":
        if state.get("planted"):
            cur = load_state()
            ev = {"enclave_conduit": ENCLAVE_SECRET}
            res = finish(cur, ev, extra={"enclave": "design enclave",
                                            "persistence": "keystroke-log"})
            return "enclave> " + str(res.get("flag", "")) + "\n$ "
        return "enclave: no session (this host is not the enclave)\n$ "
    return "'" + line.split()[0] + "' is not recognised.\n$ "


def serve():
    boot()

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                data = b""
                try:
                    data = self.request.recv(4096)
                except Exception:
                    return
                head = data.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
                if head.startswith((b"GET ", b"HEAD ", b"POST ", b"OPTIONS")):
                    body = (b'{"status": "ok"}' if b"/healthz" in head
                            else b'{"error": "not found"}')
                    code = (b"200 OK" if b"/healthz" in head
                            else b"404 Not Found")
                    self.request.sendall(
                        b"HTTP/1.1 " + code + b"\r\n"
                        b"Content-Type: application/json\r\n"
                        + f"Content-Length: {len(body)}\r\n".encode()
                        + b"Connection: close\r\n\r\n" + body)
                    return
                self.request.sendall(b"plant engineering host\nsh$ ")
                self.request.settimeout(3.0)
                buf = data
                state = {}
                try:
                    while len(buf) < 8192:
                        chunk = self.request.recv(4096)
                        if not chunk:
                            break
                        buf += chunk
                except socket.timeout:
                    pass
                replies = []
                for ln in buf.decode("utf-8", "replace").splitlines():
                    if ln.strip():
                        replies.append(run(state, ln.strip()))
                self.request.sendall("".join(replies).encode())
            except Exception:
                pass

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    srv = Server(("0.0.0.0", PLAYER_PORT), Handler)
    print(f"[plant] service on :{PLAYER_PORT}", flush=True)
    print(f"[plant] flag server: {FLAG_SERVER or '(unset - offline)'}",
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    serve()