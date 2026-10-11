# OSINT

4 challenges. Static — everything you need is in `artifacts/`, and nothing
needs to be running.

The through-line is **corroboration**. Each of these hands you one source and
tells you, in the case file, that another source contradicts it. The reflex to
train is to trust the copy you were handed; the exercise is to go and check it
against something authoritative.

| ID | Name | Difficulty | Flag |
|---|---|---|---|
| SIM-01 | No Station Recorded It | Easy | `n0st4ti0nrec0rdedit` |
| SIM-02 | GEM/2026/B/4471021, Corrigendum II | Easy | `0netenderthreerevisi0ns` |
| SIM-03 | NICeMail, 06:14 | Medium | `bin4riesrun0nindi4ncl0ck` |
| SIM-04 | Kavach Download | Medium | `4dsp4yf0rthef4ked0wnl04d` |

---

## SIM-01 — No Station Recorded It

A public rainfall and outage advisory feed has been falsified. Somebody with
routine write access published a line that does not belong there.

**Step 1 — find the falsified bulletin.** The case file gives you the
corroboration to check against: *the 5 August 2025 IMD press copy records that
no station met the cloudburst threshold at Dharali*. Go to
`press/monsoon_2025_salient_features.txt` and read the `dharali:` line.

```console
$ grep -A2 dharali artifacts/press/monsoon_2025_salient_features.txt
dharali: 5 August 2025, Dharali (Uttarkashi): no rainfall station in the
vicinity recorded precipitation meeting the formal cloudburst threshold
(>100 mm in one hour)
```

So: a bulletin claiming a cloudburst on 5 August 2025 is the forgery. Only one
of them claims one.

**Step 2 — check it against the station registry.** The bulletin names station
`ARG-0471` at 128.4 mm. Look it up:

```console
$ grep ARG-0471 artifacts/registry/stations.csv
(no output)
```

The station does not exist. That is SANDVIPER's error — they copied the mirror
faithfully but did not check the station registry.

**Step 3 — decode the collector grid.** The forged bulletin carries a
collector grid. `collector_grid.txt` explains it: a four-column table of two
digit base-62 indices, filled **column by column, top to bottom**, skipping
blanks.

Use the JSON, not the `.txt`. The text render drops the fifth row — the same
copying sloppiness.

```python
import json
ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
g = json.load(open("artifacts/feed/ADV-0314.json"))["collector_grid"]
print("".join(ALPHA[g[r][c]] for c in range(4) for r in range(len(g))
              if g[r][c] is not None))
# n0st4ti0nrec0rdedit
```

```
flag: n0st4ti0nrec0rdedit
```

> Decrypting the four rows in the `.txt` render gives `n0stti0rec0dedi` —
> fifteen characters, wrong. The JSON has five rows. That difference is the
> whole reason the challenge says "they left one error in every bundle".

---

## SIM-02 — GEM/2026/B/4471021, Corrigendum II

Four revisions of a tender document, two corrigenda, and the most conspicuous
thing in the bundle is a decoy.

Corrigendum I reinstates **Annexure-D, the price schedule**, at length. Read
it carefully. It is not the answer.

The asset nomenclature table — **Annexure-C** — survives in full only at
**revision 1**. Revisions 2 and 3 repeat it, revision 4 drops it entirely, and
Corrigendum II carries only two example rows forward.

So work backwards through publication order until the table is whole:

```console
$ grep -l 'Annexure-C -- ASSET NOMENCLATURE' artifacts/tender/*.txt
GEM-2026-B-4471021_rev01.txt
GEM-2026-B-4471021_rev02.txt
GEM-2026-B-4471021_rev03.txt
```

Revisions 2 and 3 are truncated; revision 1 is the complete table. Read its
code column:

```
PRG/B12-765KV/IED-C    306e6574656e6465727468726565726576697369306e73
```

That hex decodes to the flag.

```
flag: 0netenderthreerevisi0ns
```

> **Three revisions, one answer.** The corrigenda exist to send you to the
> price schedule. If you read the largest, boldest document first, you have
> already lost.

---

## SIM-03 — NICeMail, 06:14

A forwarded photograph. Whatever the camera wrote is still in the JPEG.

```console
$ python3 -c "from PIL import Image; im=Image.open('artifacts/photos/hackathon.jpg');     print(im.getexif().get(0x010e))"
WHITEBOARD (photographed, transcription in EXIF ImageDescription)
```

`ImageDescription` (tag `0x010E`) is a pointer, not the content. The content is
in `UserComment` (tag `0x9286`), and that one is base64 with a `b64:` prefix:

```console
$ python3 -c "
from PIL import Image; import base64
uc = str(Image.open('artifacts/photos/hackathon.jpg').getexif().get(0x9286))
print(base64.b64decode(uc[4:]).decode())
"
WHITEBOARD (photographed, transcription in EXIF ImageDescription)
------------------------------------------------------
B12 765kV line1: need IED-D signing BEFORE monsoon
  -> firmware channel: ppg-fw-build-nightly
  -> KDF salt comes from the manifest, NOT the source
  -> do NOT trust rev4, the nomenclature came back in corr-II
  -> OCS admin is firstname.lastname  (see ops-ocs-02)
------------------------------------------------------
receipt: 62696e347269657372756e306e696e6469346e636c30636b
```

The hex on the `receipt:` line is the flag:

```
flag: bin4riesrun0nindi4ncl0ck
```

> The whiteboard is only half the challenge — it points at `ops-ocs-02`, which
> is in the directory CSV, and at the firmware channel, which is in the CI log.
> The receipt alone satisfies the flag, but the cross-references are what make
> it Medium rather than Easy.

---

## SIM-04 — Kavach Download

A firmware drop link, recovered from a set of search-result captures and a
researcher's notes.

The trap is in the method. The obvious filter — "the domain appears in every
search capture" — is not sufficient, and the reference file says why:

> A registered domain also drops out of one window (availability), so 'present
> in all' alone is not sufficient.

So you need two conditions together: present in the captures **and** absent from
the availability window, which is what rules out the legitimately registered
domain that happens to appear everywhere.

```console
$ cat artifacts/ads/researcher_notes.txt
$ cat artifacts/reference/nic_domains.txt
```

Cross-reference the ads, drop the registered domain, and the download path is
what remains.

```
flag: 4dsp4yf0rthef4ked0wnl04d
```

> Written from the reference material rather than a full decode. The
> availability cross-check is the part the case file is really testing — a
> domain registered to the vendor appears in every capture too, and taking it
> sends you to an empty bucket.
