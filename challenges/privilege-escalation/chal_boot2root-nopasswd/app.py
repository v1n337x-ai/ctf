#!/usr/bin/env python3
"""
Velammal Engineering College CTF SIM-28 -- "NOPASSWD" (jump host)

An operator shell on the jump host. sudo has a NOPASSWD rule for one
helper, and the helper sources a file out of a directory the group can
write to. The rule is not the bug. What the program opens is the bug.
"""
import hashlib
import hmac
import json
import os
import sys
import socket
import socketserver
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

PLAYER_PORT = int(os.environ.get("PLAYER_PORT", "2223"))
FLAG_SERVER = os.environ.get("FLAG_SERVER_URL", "").rstrip("/")
REGISTER_TOKEN = os.environ.get("VEC_REGISTER_TOKEN", "")
CHAL_ID = os.environ.get("CHAL_ID", "SIM-28")
STATE_DIR = os.environ.get("STATE_DIR", "/app/state")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
OUTCOME = os.path.join(STATE_DIR, "outcome.txt")

JUMPHOST_SECRET = ""

def set_objective(value):
    """This instance's protected value, issued by the flag server."""
    global JUMPHOST_SECRET
    JUMPHOST_SECRET = value


HELPER_CONFIG = "/srv/deploy/etc/helper.env"     # group-writable
FILES = {
    HELPER_CONFIG: "# deploy helper config\nVERBOSE=1\n",
    "/home/ops/.bashrc": "# ops\n",
}


def whoami(level):
    return {0: "ops", 1: "root"}[level]


class Session:
    def __init__(self):
        self.level = 0


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
        print("[SIM-28] FLAG_SERVER_URL unset - offline, no flag issued",
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
        print("[SIM-28] registered " + st["instance_id"], file=sys.stderr)
    except Exception as exc:
        print("[SIM-28] registration failed: " + str(exc), file=sys.stderr)
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
        print("[SIM-28] flag request failed: " + str(exc), file=sys.stderr)
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
        print("[SIM-28] OBJECTIVE MET " + st["instance_id"], flush=True)
    payload = {"objective": "complete", "flag": st.get("flag")}
    if extra:
        payload.update(extra)
    return payload


def root_flag(cur):
    ev = {"jumphost_sudo": JUMPHOST_SECRET}
    return finish(cur, ev, extra={"id": whoami(1),
                                     "note": "escalated on the jump host"})


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
                if head.startswith((b"GET ", b"HEAD ", b"POST ",
                                    b"OPTIONS")):
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
                self.request.sendall(b"jump host: ssh ops@jump-host\n$ ")
                sess = Session()
                self.request.settimeout(3.0)
                buf = data
                try:
                    while len(buf) < 8192:
                        chunk = self.request.recv(4096)
                        if not chunk:
                            break
                        buf += chunk
                except socket.timeout:
                    pass
                replies = []
                for line in buf.decode("utf-8", "replace").splitlines():
                    if not line.strip():
                        continue
                    replies.append(self.run(sess, line.strip()))
                self.request.sendall("".join(replies).encode())
            except Exception:
                pass

        def run(self, sess, line):
            if line in ("whoami",):
                return f"ops\n$ "
            if line == "sudo -l":
                return ("User ops may run the following commands:\n"
                        "    (ALL) NOPASSWD: /usr/local/sbin/deploy-helper\n"
                        "$ ")
            if line == "/usr/local/sbin/deploy-helper":
                # the helper sources a file the group can write; if that
                # file contains ESCALATE=, it runs as root
                cfg = FILES.get(HELPER_CONFIG, "")
                if "ESCALATE=1" in cfg:
                    cur = load_state()
                    res = root_flag(cur)
                    return (f"deploy-helper: applying config\n"
                            f"flag={res.get('flag','')}\n$ ")
                return ("deploy-helper: config ok, nothing to do\n$ ")
            if line.startswith("cat "):
                path = line[4:].strip()
                if path in FILES:
                    return FILES[path] + "$ "
                return f"cat: {path}: No such file\n$ "
            if line.startswith("echo ") and ">" in line:
                payload, _, path = line[5:].partition(">")
                path = path.lstrip(">").strip()
                if path in FILES:
                    FILES[path] = FILES[path] + payload.strip() + "\n"
                    return f"$ "
                return f"bash: {path}: Permission denied\n$ "
            if line == "ls -la /srv/deploy/etc":
                return ("-rw-rw---- 1 ops deploy  helper.env\n$ ")
            return "bash: command not found\n$ "

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    srv = Server(("0.0.0.0", PLAYER_PORT), Handler)
    print(f"[web18] jump host on :{PLAYER_PORT}", flush=True)
    print(f"[web18] flag server: {FLAG_SERVER or '(unset - offline)'}",
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    serve()