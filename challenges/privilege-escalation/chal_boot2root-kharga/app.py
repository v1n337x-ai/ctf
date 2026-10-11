#!/usr/bin/env python3
"""
Velammal Engineering College CTF SIM-27 -- "Kharga" (field-office workstation)

The lockdown on this machine is an access control list, and access
control lists can be enumerated by anyone who logs in. The scheduled
backup task runs a file the domain logon can write.
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

PLAYER_PORT = int(os.environ.get("PLAYER_PORT", "2222"))
FLAG_SERVER = os.environ.get("FLAG_SERVER_URL", "").rstrip("/")
REGISTER_TOKEN = os.environ.get("VEC_REGISTER_TOKEN", "")
CHAL_ID = os.environ.get("CHAL_ID", "SIM-27")
STATE_DIR = os.environ.get("STATE_DIR", "/app/state")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
OUTCOME = os.path.join(STATE_DIR, "outcome.txt")

WORKSTATION_SECRET = ""

def set_objective(value):
    """This instance's protected value, issued by the flag server."""
    global WORKSTATION_SECRET
    WORKSTATION_SECRET = value


ACL = {
    r"C:\lockdown\backup.cmd": "(D) Modify   NACH\\Domain Users",
    r"C:\Program Files\engineer-console": "(R) Read   NACH\\Domain Users",
    r"C:\Windows\System32": "(R) Read       NACH\\Domain Users",
}


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
        print("[SIM-27] FLAG_SERVER_URL unset - offline, no flag issued",
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
        print("[SIM-27] registered " + st["instance_id"], file=sys.stderr)
    except Exception as exc:
        print("[SIM-27] registration failed: " + str(exc), file=sys.stderr)
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
        print("[SIM-27] flag request failed: " + str(exc), file=sys.stderr)
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
        print("[SIM-27] OBJECTIVE MET " + st["instance_id"], flush=True)
    payload = {"objective": "complete", "flag": st.get("flag")}
    if extra:
        payload.update(extra)
    return payload


def award(reason):
    cur = load_state()
    ev = {"workstation_acl": WORKSTATION_SECRET}
    res = finish(cur, ev, extra={"privilege": "NT AUTHORITY\\SYSTEM",
                                    "note": reason})
    return "system> " + str(res.get("flag", "")) + "\n$ "


def run(state, line):
    if line == "whoami":
        return ("nakh\\field-ops\n$ " if state["level"] == 0
                else "nt authority\\system\n$ ")
    if line == "id":
        return ("uid=1101(field-ops) groups=1101,1102(engineers)\n$ "
                if state["level"] == 0 else "uid=1000(system)\n$ ")
    if line == "help":
        return ("    whoami | id | icacls | write | schtasks | cat\n$ ")
    if line == r"icacls C:\lockdown /enumerate":
        out = ["Successfully processed 3 entries"]
        for path, acl in ACL.items():
            out.append(f"{path}\n    {acl}")
        return "\n".join(out) + "\n$ "
    if line.startswith("write "):
        parts = line.split(" ", 2)
        if len(parts) == 3:
            state["task_file"] = parts[1]
            state["task_body"] = parts[2]
            return "1 file(s) written\n$ "
        return "bad arguments\n$ "
    if line == "schtasks /run /tn lockdown-backup":
        body = state.get("task_body", "")
        if state.get("task_file") and ("whoami" in body
                                       or "SYSTEM" in body.upper()):
            state["level"] = 1
            return award("lockdown-backup executed your file as SYSTEM")
        return "schtasks: task started; log line: ok\n$ "
    if line.startswith("cat "):
        path = line[4:].strip()
        if path in ACL:
            return path + "\n    " + ACL[path] + "\n$ "
        return "The system cannot find the file specified.\n$ "
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
                self.request.sendall(b"kharga field-office workstation\nC:\\$ ")
                self.request.settimeout(3.0)
                buf = data
                state = {"level": 0}
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
    print(f"[workstation] service on :{PLAYER_PORT}", flush=True)
    print(f"[workstation] flag server: "
          f"{FLAG_SERVER or '(unset - offline)'}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    serve()