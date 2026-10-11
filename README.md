# VEC CTF

**Capture The Flag** - a hands-on cybersecurity workshop at **Velammal
Engineering College**, Department of CSE (Cyber Security).

| | |
|---|---|
| Dates | 06 October 2026 & 07 October 2026 |
| Time | 10:30 AM - 4:00 PM |
| Venue | Cyber Security Lab |
| Institute | Velammal Engineering College (An Autonomous Institution) |
| Organised by | Department of CSE (Cyber Security), with Digialert |

This repository contains the challenges from the event, the reference flag
server, and a walkthrough for every one of them.

---

## Contents

```
ctf/
├── challenges/
│   ├── web/                      10 challenges  - the main track
│   ├── binary-exploitation/       4 challenges  - memory corruption
│   ├── privilege-escalation/      6 challenges  - Active Directory / Linux
│   ├── ai-security/               3 challenges  - LLM application security
│   ├── forensics/                 5 challenges  - disk and protocol analysis
│   ├── osint/                     4 challenges  - open-source intelligence
│   ├── reverse-engineering/       7 challenges  - binaries and protocols
│   └── crypto/                    1 challenge   - classical cryptography
└── flag-server/                  the reference scoring server
```

Every challenge has a write-up. Where a solution was confirmed by solving it
end to end against a live flag server, the flag is shown. Where it was written
from the shipped source, the method is given in full and says so.

---

## Getting started

You need **Python 3** and, for the network challenges, **Docker**.

```bash
git clone <this-repo>
cd ctf
```

Pick a category, read its README, and start with the easier challenges - each
one has a difficulty label and, for the service challenges, an entry point you
can reach in a browser.

Every service challenge is self-contained. Inside a challenge folder:

```bash
cd challenges/web/chal_web-udgam
./run.sh
```

The script reads its own configuration, checks the flag server is reachable,
and starts the service. You do not need to edit anything.

When you meet the objective, the flag arrives from the flag server and is
written to `state/outcome.txt` in that folder. It is never shipped inside the
challenge - the handout contains 40 challenges and zero flags.

> **If `./run.sh` warns that the flag server is unreachable, keep going.**
> The challenge still works offline. Your flag is claimed automatically once
> the server is reachable again - nothing is lost.

---

## How the flag server works

A small HTTP service issues every flag. The important part is what it does
*not* do:

- There is **no endpoint that returns a flag on request.** There is no
  `GET /flag`, no index of flags, and the scoreboard carries counts only.
- A challenge **registers** with the server at startup and receives a
  per-instance secret and a per-instance objective value. Neither is in the
  handout.
- When you meet the objective, the challenge submits what it recovered to
  `/verify`, signed with the per-instance secret. **The server decides** whether
  that is correct.
- Flags are derived from a phrase pool, so a given challenge always issues the
  same flag to everyone who solves it.

This means there is no shortcut. You have to actually demonstrate the flaw.

Restarting a challenge is safe. State survives in `state/state.json`, re-running
the exploit returns the same flag, and `/claim` returns it again for an
instance that has already earned one.

```bash
curl -H 'User-Agent: Mozilla/5.0' https://<flag-server>/api/v1/scoreboard
curl -H 'User-Agent: Mozilla/5.0' https://<flag-server>/healthz
```

Send a browser `User-Agent`. A default `curl` or Python agent is refused with
HTTP 403 by the edge proxy, which looks like a dead server but is not.

See [`flag-server/README.md`](flag-server/README.md) to run your own copy.

---

## Challenges

| ID | Name | Category | Difficulty | Flag |
|---|---|---|---|---|
| SIM-01 | No Station Recorded It | OSINT | Easy | `n0st4ti0nrec0rdedit` |
| SIM-02 | GEM/2026/B/4471021, Corrigendum II | OSINT | Easy | `0netenderthreerevisi0ns` |
| SIM-03 | NICeMail, 06:14 | OSINT | Medium | `bin4riesrun0nindi4ncl0ck` |
| SIM-04 | Kavach Download | OSINT | Medium | `4dsp4yf0rthef4ked0wnl04d` |
| SIM-05 | SHA-1 Is Retired And Sigs Keep Verifying | Forensics | Medium | `sh4tteredtw0files0neh4sh` |
| SIM-06 | Section 70B | Forensics | Hard | `secti0nseventyb` |
| SIM-13 | Chitthi Is The Letter | Crypto | Easy | `thefestiv4lletter` |
| SIM-14 | Six Bytes Per Ping | Reverse Engineering | Medium | `sixbytes0neping` |
| SIM-15 | Tape Vault | Forensics | Medium | `everyfile0ncein0rder` |
| SIM-16 | Bit Vault | Forensics | Hard | `ninebitsperw0rd` |
| SIM-17 | Depth Raster | Reverse Engineering | Hard | `ther4sterre4dssidew4ys` |
| SIM-18 | GOOSE Is Layer 2 | Reverse Engineering | Medium | `g00seisl4yertw0` |
| SIM-19 | Dispatch Log | Reverse Engineering | Medium | `fl4ttenedc0ntr0lfl0w` |
| SIM-20 | Hamraaz | Reverse Engineering | Medium | `h4mr44zis4re4l4pp` |
| SIM-21 | BYOVD | Reverse Engineering | Hard | `bringy0ur0wndriver` |
| SIM-22 | NISAR Downlink | Reverse Engineering | Hard | `twelved4yst0descend` |
| SIM-35 | NACH | Forensics | Insane | `then4chcle4ringh0use` |
| WEB01 | Metadata From Cyberspace | Web | Medium | `ssrfserver4sked4n0therh0st` |
| WEB02 | Udgam | Web | Medium | `jwtresults0utsidethespec` |
| WEB03 | Right to Public Services | Web | Medium | `upl04drightt0servicescl0nes` |
| WEB04 | Vendor Master | Web | Medium | `vend0rse4rchisf4stbec4usec4ched` |
| WEB05 | Grid Code | Web | Medium | `gr4phql0nefieldnever4sked` |
| WEB06 | Availability Based Tariff | Web | Medium | `sstishiftrep0rtfr0m4templ4te` |
| WEB07 | The Consent Screen | Web | Medium | `04uththec0dec4nbech4nged1nce` |
| WEB08 | The Settlement Screen | Web | Medium | `uni0n3rderbyc0untsc0lumns` |
| WEB09 | Yesterday's Appliance | Web | Medium | `4ppli4ncedef4ultcredenti4lsneverr0t4ted` |

---

## Category walkthroughs

Each category has its own README with the full solution method, written to be
followed rather than skimmed.

| Category | Readme | Challenges |
|---|---|---|
| Web | [challenges/web/README.md](challenges/web/README.md) | 10 |
| Binary exploitation | [challenges/binary-exploitation/README.md](challenges/binary-exploitation/README.md) | 4 |
| Privilege escalation | [challenges/privilege-escalation/README.md](challenges/privilege-escalation/README.md) | 6 |
| AI security | [challenges/ai-security/README.md](challenges/ai-security/README.md) | 3 |
| Forensics | [challenges/forensics/README.md](challenges/forensics/README.md) | 5 |
| OSINT | [challenges/osint/README.md](challenges/osint/README.md) | 4 |
| Reverse engineering | [challenges/reverse-engineering/README.md](challenges/reverse-engineering/README.md) | 7 |
| Crypto | [challenges/crypto/README.md](challenges/crypto/README.md) | 1 |

---

## Ethics

These challenges are lab simulations. They exist to teach.

- Attack only the challenges in this repository.
- Do not use these techniques against systems you are not authorised to test.
- Every organisation, product and incident referenced in the challenges is
  fictional.

If you find a real vulnerability in college infrastructure, report it to the
Department of CSE rather than exploiting it.

---

## Acknowledgements

A workshop at Velammal Engineering College, Department of CSE (Cyber Security).

Resource persons **Mr. A. Abdul Gafoor** and **Mr. Vineet Sanjeev Khalkho**,
from **Digialert**.

---

*All organisations, software and incidents described in these challenges are
fictional. Any resemblance to real systems is for teaching purposes.*
