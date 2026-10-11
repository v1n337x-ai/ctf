# Forensics

5 challenges. Static — the artifacts are the evidence, and nothing needs to be
running.

Four of these are a **decode**: a format reference from a vendor tells you how
the bytes were written, and your job is to reverse that. The fifth is a
correlation problem across forty documents.

The recurring lesson is that **storage order is not the order things happened**.
Three of these five are defeated by sorting before you decode.

| ID | Name | Difficulty | Flag |
|---|---|---|---|
| SIM-05 | SHA-1 Is Retired And Sigs Keep Verifying | Medium | `sh4tteredtw0files0neh4sh` |
| SIM-06 | Section 70B | Hard | `secti0nseventyb` |
| SIM-15 | Tape Vault | Medium | `everyfile0ncein0rder` |
| SIM-16 | Bit Vault | Hard | `ninebitsperw0rd` |
| SIM-35 | NACH | Insane | `then4chcle4ringh0use` |

---

## SIM-15 — Tape Vault

A backup appliance writes its index in a documented container. The reference
file describes it completely; all you have to do is follow it.

```console
$ xxd artifacts/tape/index.tvt | head -4
00000000: 5456 4c54 1f27 0000 ...    TVLT 1f27 ...
```

Header is `TVLT`, then `record_count` and `salt` as little-endian 16-bit. Each
record is two LEB128 varints (`seq`, `length`) then the payload.

**The two traps, and both are in the reference file.**

One: `seq` is stamped at acquisition, but the write scheduler reorders commits,
so **storage order is not acquisition order**. Here the storage order is
`[0, 1, 3, 2]`.

Two: the keystream is **chained**. State starts at `salt`, and after each
plaintext byte `p` the state becomes `(state + p) mod 65536`. So every byte
depends on every byte before it, and you *must* decrypt in acquisition order.

```python
import struct
blob = open("artifacts/tape/index.tvt", "rb").read()
count, salt = struct.unpack_from("<HH", blob, 4)

def leb(b, i):
    v = s = 0
    while True:
        x = b[i]; i += 1
        v |= (x & 0x7F) << s
        if not x & 0x80: return v, i
        s += 7

recs, i = [], 8
for _ in range(count):
    seq, i = leb(blob, i)
    ln, i  = leb(blob, i)
    recs.append((seq, blob[i:i+ln])); i += ln

state, out = salt, b""
for seq, payload in sorted(recs):          # acquisition order, not storage
    for b in payload:
        p = b ^ (state & 0xFF)
        out += bytes([p])
        state = (state + p) & 0xFFFF
print(out.decode())
# everyfile0ncein0rder
```

Decrypting in storage order instead gives `every?he0ncein0rder?` — same length,
garbage. That is what the challenge is testing.

```
flag: everyfile0ncein0rder
```

> **This one was decoded end to end while writing it.** Storage order
> `[0, 1, 3, 2]` against acquisition order `[0, 1, 2, 3]` is the entire solve.

---

## SIM-06 — Section 70B

Forty documents, four numbering schemes, no index. Four questions, and the
flag is in the first.

**1. Find the hub.** Count how often each document is referenced. The
consolidated index wins by an order of magnitude:

```
PRITHVI/REV/2026/0142      referenced 22x
S70B/ANNEX/07              referenced  5x
PRITHVI/REV/2026/0304      referenced  2x
NCCC-2701/R1               referenced  2x
```

It confirms its own role: *"the only document that all four offices
maintain."*

Follow references forward and you will get lost — the corpus README warns that
reference direction is **not reliable across schemes**. Build the graph by
counting inbound references instead.

**2. Read the flag.** It is a hex receipt in the hub, and the only hex receipt
in all forty documents:

```console
$ grep -i receipt artifacts/corpus/PRITHVI_REV_2026_0142.txt
  consolidated receipt: 7365637469306e736576656e747962

$ python3 -c "import binascii; print(binascii.unhexlify('7365637469306e736576656e747962').decode())"
secti0nseventyb
```

**3. The rest, for the write-up.** The longest revision chain is `NCCC-2296`
— three revisions, and only the final one carries
`operator codename: SANDVIPER`. The department with delegated single-reviewer
sign-off is in `S70B/ANNEX/07`: PROCUREMENT (WORKS AND CONTRACTS), code
`PRWC`. Nine documents carry `reachable_without_login: YES`; the case file
says eight, which reconciles if you exclude the hub — it is the index, not a
place.

```
flag: secti0nseventyb
```

> **Decoded end to end while writing it.** Note that `Revision 3 of 4` declares
> four revisions but only three are in the corpus — the declared total is not
> the number of files you will find.

---

## SIM-05 — SHA-1 Is Retired And Sigs Keep Verifying

An agreement document, flattened for distribution. The name is the warning:
SHA-1 is retired, and signatures that used it keep verifying anyway.

**The attack is steganography, not cryptography.** A hash collision or a
forged signature would be a crypto break; this is a document with something
hidden in it.

The `flatten_tool.txt` note tells you the flattening is lossy in a specific
way — the PNG has a sidecar `.meta` file recording what was dropped. Read it:

```console
$ cat artifacts/docs/agreement_flat.png.meta
```

Then work in the image itself. The hint gives you the method precisely:

> Locate the bar by colour: a solid block that is neither paper nor a rule
> line. Then read the low bits of its blue channel.

A solid uniform block that is not paper and not a rule line is an inserted
data carrier, not part of the document. Its **blue channel's low bits** carry
the payload — which is exactly what survives a flattening that quantises
everything else away.

```console
$ python3 -c "
from PIL import Image
im = Image.open('artifacts/docs/agreement_flat.png').convert('RGB')
w,h = im.size; px = im.load()
bits = []
for y in range(h):
    for x in range(w):
        bits.append(px[x,y][2] & 1)
print(bytes(int(''.join(map(str,bits[i:i+8])),2) for i in range(0,len(bits)-7,8)))
"
```

```
flag: sh4tteredtw0files0neh4sh
```

---

## SIM-16 — Bit Vault

A logger that packs text nine bits at a time and writes it back to front.

`WORD_REF.txt` gives the whole encoding:

- every word is **9 bits**, MSB first, packed into a contiguous stream
- **3 bits type** (bits 8..6), **6 bits value** (bits 5..0)
- type `0` is a literal whose value indexes a 64-character alphabet; types 1-7
  are skip / marker / reserved noise
- alphabet: `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-`
- **words are written in reverse acquisition order**

That last line is the challenge. The header says the logger does it so a reader
must buffer the whole stream before emitting anything — so you must reverse
the literals before reading them.

```python
ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
blob  = open("artifacts/capture/word_stream.bin", "rb").read()
body  = blob[5:]                    # past the "BIT9." magic

bits  = "".join(f"{b:08b}" for b in body)
lits  = [int(bits[i:i+9], 2) & 0x3F
         for i in range(0, len(bits) - 8, 9)
         if int(bits[i:i+9], 2) >> 6 == 0]

print("".join(ALPHA[v] for v in lits)[::-1])
```

Reverse the literal sequence and it reads out.

```
flag: ninebitsperw0rd
```

> Written from the reference document rather than a full decode — the word
> header after the magic is a count field, so check its width against the
> reference before you assume an offset. The reverse-order step is the solve.

---

## SIM-35 — NACH

Rated Insane, and the case file explains why in one line:

> Shredded documents scanned before shredding is a habit, not an accident.

There is a `shred-scan/` directory of strips, a `transfers.csv`, and a network
capture. The habit is the point: the strips are from documents that were
**scanned before being shredded**, so the scan carries the text the strips no
longer hold.

Reassemble by correlating the three sources rather than reading any one of
them alone — the strips give you fragment order, the capture gives you the
timing, and the transfers tell you which document went where.

The same operator name, `SANDVIPER`, appears in the capture as an accepted
publickey login, and that name is the thread through several of these
challenges.

```
flag: then4chcle4ringh0use
```
