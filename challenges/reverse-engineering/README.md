# Reverse engineering

7 challenges in this category.

## Challenges

| ID | Name | Difficulty | Flag |
|---|---|---|---|
| `SIM-14` | Six Bytes Per Ping | Medium | `sixbytes0neping` |
| `SIM-17` | Depth Raster | Hard | `ther4sterre4dssidew4ys` |
| `SIM-18` | GOOSE Is Layer 2 | Medium | `g00seisl4yertw0` |
| `SIM-19` | Dispatch Log | Medium | `fl4ttenedc0ntr0lfl0w` |
| `SIM-20` | Hamraaz | Medium | `h4mr44zis4re4l4pp` |
| `SIM-21` | BYOVD | Hard | `bringy0ur0wndriver` |
| `SIM-22` | NISAR Downlink | Hard | `twelved4yst0descend` |

---

### SIM-14 - Six Bytes Per Ping

**Category** Reverse Engineering · **Difficulty** Medium

**Approach.** `seq` is stamped at capture time, not at write time. Several capture threads interleave, so storage order is not acquisition order.

```
flag: sixbytes0neping
```

### SIM-17 - Depth Raster

**Category** Reverse Engineering · **Difficulty** Hard

**Approach.** The RLE encodes runs of identical pixels. Expand it into a flat array, then read it row by row to recover the row-major raster.

```
flag: ther4sterre4dssidew4ys
```

### SIM-18 - GOOSE Is Layer 2

**Category** Reverse Engineering · **Difficulty** Medium

**Approach.** Stored form is rotate right 3 then XOR 0x5A. Rotation is not symmetric.

```
flag: g00seisl4yertw0
```

### SIM-19 - Dispatch Log

**Category** Reverse Engineering · **Difficulty** Medium

**Approach.** The trace is the whole program. Execute the records in order from a register file of zeros, de-obfuscating each opcode as you read it.

```
flag: fl4ttenedc0ntr0lfl0w
```

### SIM-20 - Hamraaz

**Category** Reverse Engineering · **Difficulty** Medium

**Approach.** Recompute the checksum over the embedded payload yourself.

```
flag: h4mr44zis4re4l4pp
```

### SIM-21 - BYOVD

**Category** Reverse Engineering · **Difficulty** Hard

**Approach.** Rebuild the dispatch table from the IOCTL handler and read the key schedule it runs at init.

```
flag: bringy0ur0wndriver
```

### SIM-22 - NISAR Downlink

**Category** Reverse Engineering · **Difficulty** Hard

**Approach.** Read the signature check and find what it does not check.

```
flag: twelved4yst0descend
```

