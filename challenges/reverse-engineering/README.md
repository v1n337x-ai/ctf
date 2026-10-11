# Reverse engineering

7 challenges. Static — binaries and capture files in `artifacts/`.

The pattern here is **a documented format plus one non-obvious property**.
Every one of these vendors published a reference for the container; the
challenge is entirely in the part the reference glosses over. Read what the
format *is*, then find the thing it does not tell you.

| ID | Name | Difficulty | Flag |
|---|---|---|---|
| SIM-14 | Six Bytes Per Ping | Medium | `sixbytes0neping` |
| SIM-17 | Depth Raster | Hard | `ther4sterre4dssidew4ys` |
| SIM-18 | GOOSE Is Layer 2 | Medium | `g00seisl4yertw0` |
| SIM-19 | Dispatch Log | Medium | `fl4ttenedc0ntr0lfl0w` |
| SIM-20 | Hamraaz Is Real | Medium | `h4mr44zis4re4l4pp` |
| SIM-21 | BYOVD | Hard | `bringy0ur0wndriver` |
| SIM-22 | NISAR Downlink | Hard | `twelved4yst0descend` |

---

## SIM-14 — Six Bytes Per Ping

A telemetry logger writes fixed-size records. `FIELD_REF.txt` gives the
container: a 12-byte header (`TLM1`, `record_count`, reserved, `total_bits`)
then `record_count` six-byte records of `seq`, a bit-field word, and a `crc16`.

The field reference tells you the layout. It does not tell you the thing that
matters:

> `seq` is stamped at capture time, not at write time. Several capture threads
> interleave, so **storage order is not acquisition order**.

So records are on disk in whatever order four threads finished writing them.
Sort by `seq` before you read the bit fields.

```python
import struct
blob = open("artifacts/capture/ping_log.tlm", "rb").read()
count = struct.unpack_from("<H", blob, 4)[0]
recs = [struct.unpack_from("<HHH", blob, 12 + i * 6) for i in range(count)]
for seq, bits, crc in sorted(recs):        # acquisition order, not storage
    ...
```

The bit fields are then read out of the 6-character commissioning alphabet in
`channel_alphabet.txt`.

```
flag: sixbytes0neping
```

> **Sort first, decode second.** Every other part of this file is documented
> and therefore free.

---

## SIM-17 — Depth Raster

A run-length encoded 1-bit raster. `RASTER_REF.txt` describes both halves of
the problem, and the second half is the whole challenge:

The RLE stores `(count, value)` byte pairs and encodes the image **column by
column, top to bottom**. To get the picture you must expand it to a flat
`width × height` array and then read it **row by row**.

```python
blob = open("artifacts/capture/depth.rstr", "rb").read()
flat = []
for i in range(0, len(blob) - 1, 2):
    count, value = blob[i], blob[i + 1]
    flat.extend([value] * count)          # column-major expansion
```

Then transpose on read — row `y`, column `x` is `flat[x * height + y]`, not
`flat[y * width + x]` — and render with the 5x7 bitmap font in `FONT.txt`.

Reading it in the wrong order gives you a scrambled image that looks like
corruption rather than a transposed raster. That is the trap.

```
flag: ther4sterre4dssidew4ys
```

---

## SIM-18 — GOOSE Is Layer 2

An IEC 61850 GOOSE frame from an IoT meter firmware. The `HANDLING_NOTE.txt`
records the stored transform, and it is the whole challenge:

> Stored form is **rotate right 3 then XOR 0x5A**. Rotation is not symmetric.

To invert it you must **undo the XOR first, then rotate left 3**. The order is
not interchangeable — rotating then XORing is not the same function, and if you
de-obfuscate in the wrong order you get noise and go looking for a different
bug.

```python
data = open("artifacts/telemetry/goose_frame.blob", "rb").read()

def ror3(b):  return ((b >> 3) | (b << 5)) & 0xFF
def rol3(b):  return ((b << 3) | (b >> 5)) & 0xFF

out = bytes(rol3(b ^ 0x5A) for b in data)   # XOR undone first, then rotate
```

`build_manifest.json` has the block structure so you can find where the ASCII
payload starts.

```
flag: g00seisl4yertw0
```

> GOOSE is unencrypted by design — it is Layer 2 multicast on the operational
> network. That is why this exists at all, and why the frame is readable by
> anyone on the segment.

---

## SIM-19 — Dispatch Log

A trace of a tiny instruction set. `ISA_REF.txt` gives the opcodes.

The hint is blunt about the method:

> The trace is the whole program. Execute the records in order from a register
> file of zeros, de-obfuscating each opcode as you read it.

So this is not disassembly, it is **interpretation**. Start with every register
at zero, walk the records in order, apply each operation, and read the register
file at the end.

```python
regs = [0] * 8
for rec in sorted(records, key=lambda r: r.seq):
    op, *args = decode(rec)          # the de-obfuscation is per-opcode
    regs = apply(op, args, regs)
print(regs)
```

Each opcode is obfuscated differently, which is why the reference tells you to
de-obfuscate "as you read it" rather than in a separate pass — the decode
depends on where you are in the program.

```
flag: fl4ttenedc0ntr0lfl0w
```

---

## SIM-20 — Hamraaz Is Real

A signed binary with an embedded payload. The hint is the shortest in the set
and it is also the whole solve:

> **Recompute the checksum yourself.**

So do not trust the embedded checksum — recompute it over the payload region
and compare. If they disagree, you have found the region that was altered, and
that region is where the flag is.

```console
$ file artifacts/hamraaz
$ ./artifacts/hamraaz --help
```

Strip the loader, locate the signed region, recompute, diff.

```
flag: h4mr44zis4re4l4pp
```

---

## SIM-21 — BYOVD

A vulnerable driver. The hint tells you the method and the order:

> **Rebuild the dispatch table from the IOCTL handler and read the key schedule
> it runs at init.**

IOCTL dispatch tables are a table of function pointers indexed by control code.
Rebuild it from the handler's switch, and the gap between the codes it handles
and the codes it does not is the interesting part.

Then find the key schedule run at initialisation — drivers that validate a
signed command almost always do it before the buffer is trusted, and the
schedule is usually in `.init_array`.

```console
$ file artifacts/byovd_drv
$ objdump -d artifacts/byovd_drv | less
$ objdump -h artifacts/byovd_drv        # look for .init_array
```

```
flag: bringy0ur0wndriver
```

> **Bring Your Own Vulnerable Driver** is a real and well-documented class:
> a signed driver with a signed-but-vulnerable helper, where the signing
> authority vouches for the driver and not for the code behind it.

---

## SIM-22 — NISAR Downlink

Another signed payload, different lesson. The hint is a question:

> Read the signature check and find **what it does not check**.

This is signature-wrapping. The verifier checks that a block is signed — and
does not check *which* data it covers. So the signed block is left intact and
the payload is replaced with one of the same length.

The tell is a length field, or the absence of one. If the verifier hashes a
range you can influence, or if it hashes a header that does not include the
payload length, that is the bug.

```console
$ file artifacts/nicar
$ ./artifacts/nicar --verify
```

Replace the payload without touching the signed region.

```
flag: twelved4yst0descend
```
