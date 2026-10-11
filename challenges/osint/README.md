# OSINT

4 challenges in this category.

## Challenges

| ID | Name | Difficulty | Flag |
|---|---|---|---|
| `SIM-01` | No Station Recorded It | Easy | `n0st4ti0nrec0rdedit` |
| `SIM-02` | GEM/2026/B/4471021, Corrigendum II | Easy | `0netenderthreerevisi0ns` |
| `SIM-03` | NICeMail, 06:14 | Medium | `bin4riesrun0nindi4ncl0ck` |
| `SIM-04` | Kavach Download | Medium | `4dsp4yf0rthef4ked0wnl04d` |

---

### SIM-01 - No Station Recorded It

**Category** OSINT · **Difficulty** Easy

**Approach.** The 5 August 2025 IMD press copy records that no station met the cloudburst threshold at Dharali. Corroborate the forged claim against it.

```
flag: n0st4ti0nrec0rdedit
```

### SIM-02 - GEM/2026/B/4471021, Corrigendum II

Four revisions of a tender document plus two corrigenda, and the two documents
that look like the answer are decoys.

Corrigendum I reinstates Annexure-D, the price schedule, and it is the most
conspicuous thing in the bundle. It is not the answer. Annexure-C, the asset
nomenclature table, survives in full only at **revision 1** - later revisions
drop it and the corrigenda only carry examples forward.

Work backwards through the publication order until you find the revision with
the table intact, and read the code column.

```
flag: 0netenderthreerevisi0ns
```

### SIM-03 - NICeMail, 06:14

The photograph still holds whatever the camera wrote.

```console
$ python3 -c "from PIL import Image; im=Image.open('hackathon.jpg');     print(im.getexif().get(0x010e))"
WHITEBOARD (photographed, transcription in EXIF ImageDescription)
```

`ImageDescription` points at `UserComment` (tag `0x9286`), which is base64
with a `b64:` prefix. Decoded, it is a photographed whiteboard:

```
receipt: 62696e347269657372756e306e696e6469346e636c30636b
-> firmware channel: ppg-fw-build-nightly
-> OCS admin is firstname.lastname  (see ops-ocs-02)
```

The hex on the `receipt:` line is the flag. The whiteboard also points into
the directory CSV and the CI log, which is the three-way cross-reference that
makes this one harder than it looks.

```
flag: bin4riesrun0nindi4ncl0ck
```

### SIM-04 - Kavach Download

**Category** OSINT · **Difficulty** Medium

**Approach.** Cross-check against reference/nic_domains.txt. A registered domain also drops out of one window (availability), so 'present in all' alone is not sufficient.

```
flag: 4dsp4yf0rthef4ked0wnl04d
```

