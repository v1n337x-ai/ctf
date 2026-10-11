#!/usr/bin/env python3
"""
VEC flag server -- per-challenge verifiers.

Why this file exists
--------------------
Every challenge ships to the player as a local bundle they run on their own
machine, so the client is untrusted: the player controls the code, the files
and the process. Nothing the client says about its own progress can be
believed, and nothing the client holds can be treated as secret.

The decision therefore lives here. At registration the flag server mints a
per-instance objective value and hands it to the app, which writes it into
its own data store at boot. The challenge's vulnerability leaks it. The
solver submits what they extracted, and this server compares it against the
copy it kept.

    flag server --mints--> objective value --injected into--> the challenge
    the challenge --leaks (only via the intended attack)--> the solver
    solver --submits--> verifier --compares against the server's copy--> flag

Why this is not a digest
------------------------
An earlier version compared HMAC digests of the answer, with the answer
hardcoded in the app. That protects nothing here: the answer ships to the
player inside their own app.py, so they hold both the plaintext and the
means to compute the digest. Comparing the raw value against a per-instance
copy the player never sees is what actually closes it.

What a verifier gets
--------------------
    evidence      whatever the solved challenge submits (a dict)
    instance_id   the registered instance the submission came from
    want          the objective value this instance was issued at registration

What it returns
---------------
    True/False    whether the objective is demonstrated
    str           optional note for the audit log, never shown to players

Anti-replay and isolation live in flag_server.py: a submission is bound by
HMAC to the instance that registered, a verifier is keyed by challenge so
WEB01's value can never release WEB02's flag, and each instance's value is
unique so a value taken from another team's machine is worthless.
"""
import hmac
import re

# challenge id -> the evidence key whose value is the protected material.
# This is the whole contract between a challenge and its verifier: the app
# submits what its vulnerability leaked, under this name.
EVIDENCE_FIELD = {
    "WEB01": "document_note",       # aggregator: the internal document's note
    "WEB02": "restricted_record",   # session store: restricted account row
    "WEB03": "upload_secret",       # upload handler: shared storage secret
    "WEB04": "restricted_tin",      # refresh store: restricted tax identifier
    "WEB05": "cross_tenant_record", # ledger: another tenant's ledger code
    "WEB06": "historian_record",    # historian: valve tag from the historian
    "WEB07": "victim_account",      # consent screen: code bound to victim
    "WEB08": "settlement_ref",      # settlement screen: protected row ref
    "WEB09": "appliance_key",       # appliance: leaked signing key material
    "WEB10": "signing_credential",  # build agent: credential it signs with
    "SIM-23": "banner_arg",         # format string: argv built in the victim
    "SIM-24": "session_token",      # uaf: session token from freed memory
    "SIM-25": "frame_prefix",       # wrap: prefix recovered off the frame
    "SIM-26": "grant_token",        # toctou: token read inside the window
    "SIM-27": "workstation_acl",    # task ACL entry that yields the objective
    "SIM-28": "jumphost_sudo",      # sudo helper source on the jump host
    "SIM-29": "pivot_ticket",       # RC4 service ticket for the pivot
    "SIM-30": "enclave_conduit",    # version string trusted by the enclave
    "SIM-31": "dcsync_acl",         # DCSync replication ACL right
    "SIM-32": "asset_register",     # out-of-scope asset register entry
    "SIM-33": "zone_decision",      # decision boundary value
    "SIM-34": "canary_member",      # canary membership the model leaked
    "SIM-36": "console_shard",      # console trust tier shard token
}

# Some challenges only mean something if the submission also shows the shape
# of the exploit. An earlier revision required extra corroborating fields per
# challenge. That was dropped deliberately: it added no real protection (the
# player controls their own machine and can read the app's state file) while
# risking a legitimate solve being refused over one missing field. The gate is
# the value match, and it is enforced strictly.


def _norm(v) -> str:
    return re.sub(r"\s+", " ", str(v or "").strip())


def check(challenge, evidence, instance_id, want):
    """Run the verifier. Returns (ok, note). Unknown challenge => deny."""
    cid = str(challenge or "").strip().upper()
    field = EVIDENCE_FIELD.get(cid)
    if field is None:
        return False, "no verifier for this challenge"
    if not isinstance(evidence, dict):
        return False, "evidence must be an object"
    if not want:
        return False, "no objective value for this instance"

    try:
        got = evidence.get(field, "")
        if not hmac.compare_digest(_norm(got), _norm(want)):
            return False, f"wrong {field}"
        return True, f"{field} demonstrated"
    except Exception as exc:                    # noqa: BLE001
        return False, f"verifier error: {type(exc).__name__}"


def verifier_for(challenge: str):
    return EVIDENCE_FIELD.get(str(challenge or "").strip().upper())