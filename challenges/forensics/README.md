# Forensics

5 challenges in this category.

## Challenges

| ID | Name | Difficulty | Flag |
|---|---|---|---|
| `SIM-05` | SHA-1 Is Retired And Sigs Keep Verifying | Medium | `sh4tteredtw0files0neh4sh` |
| `SIM-06` | Section 70B | Hard | `secti0nseventyb` |
| `SIM-15` | Tape Vault | Medium | `everyfile0ncein0rder` |
| `SIM-16` | Bit Vault | Hard | `ninebitsperw0rd` |
| `SIM-35` | NACH | Insane | `then4chcle4ringh0use` |

---

### SIM-05 - SHA-1 Is Retired And Sigs Keep Verifying

**Category** Forensics · **Difficulty** Medium

**Approach.** Locate the bar by colour: a solid block that is neither paper nor a rule line. Then read the low bits of its blue channel.

```
flag: sh4tteredtw0files0neh4sh
```

### SIM-06 - Section 70B

Forty documents, four numbering schemes, no index. Four questions, and one of
them hides the flag.

**1. Find the hub.** Count how often each document is referenced. The
consolidated index wins by an order of magnitude:

```
PRITHVI/REV/2026/0142      referenced 22x
S70B/ANNEX/07              referenced  5x
PRITHVI/REV/2026/0304      referenced  2x
```

It confirms its own role: *"the only document that all four offices maintain."*
Follow references forward and you will get lost - the corpus explicitly warns
that reference direction is not reliable across schemes. Build the graph by
counting inbound references instead.

**2. Read the flag.** It is a hex receipt in the hub:

```console
$ grep -i receipt artifacts/corpus/PRITHVI_REV_2026_0142.txt
  consolidated receipt: 7365637469306e736576656e747962

$ python3 -c "import binascii; print(binascii.unhexlify('7365637469306e736576656e747962').decode())"
secti0nseventyb
```

That is the flag, already in its final form. It is the only hex receipt in all
40 documents, so once you have it you are done.

**3. The rest, for the write-up.** The longest revision chain is `NCCC-2296`
(three revisions; only R3 carries `operator codename: SANDVIPER`). The
department holding delegated single-reviewer sign-off is in
`S70B/ANNEX/07`: PROCUREMENT (WORKS AND CONTRACTS), code `PRWC`. Nine
documents carry `reachable_without_login: YES`; the brief's "eight" excludes
the hub, which is the index rather than a place.

### SIM-15 - Tape Vault

**Category** Forensics · **Difficulty** Medium

**Approach.** The keystream is chained: the state after each plaintext byte feeds the next byte, so records must be decrypted in acquisition order.

```
flag: everyfile0ncein0rder
```

### SIM-16 - Bit Vault

**Category** Forensics · **Difficulty** Hard

**Approach.** Words are written in reverse acquisition order: the last word acquired is the first word in the stream.

```
flag: ninebitsperw0rd
```

### SIM-35 - NACH

**Category** Forensics · **Difficulty** Insane

**Approach.** Shredded documents scanned before shredding is a habit, not an accident.

```
flag: then4chcle4ringh0use
```

