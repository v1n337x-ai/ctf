# Crypto

1 challenge. Static — the ciphertext and a crib sheet are in `artifacts/`.

| ID | Name | Difficulty | Flag |
|---|---|---|---|
| SIM-13 | Chitthi Is The Letter | Easy | `thefestiv4lletter` |

---

## SIM-13 — Chitthi Is The Letter

A letter in a substitution cipher. The crib sheet states the essentials:

- the letter opens exactly with **DEAR KAVITHA**
- simple substitution, **one letter to one letter**
- the keyword is not written down; it comes from a document the sender reads
  every day

**1. Break it with the crib.** The known opening gives you ten mappings
immediately, and a monoalphabetic substitution is a bijection, so every
mapping you add is checked against the ones you have.

```
cipher  B A P J   E P S L N O P
plain   D E A R   K A V I T H A
```

**2. Align the flag.** The ciphertext contains a literal `4` in
`NOAYAMNLS4KKAN`. The flag is `thefestiv4lletter` — 17 characters
with its `4` at the same offset. That pins the alignment:

```
NOAYAMNLS4KKAN  ->  THEFESTIV4LLET
```

**3. Fill in the rest by reading the sentence.** Once you have the flag window,
the sentence resolves word by word and the substitution completes.

```python
c2p = dict(zip("BAPJ EPSLNOP", "DEAR KAVITHA"))
c2p.update(dict(zip("NOAYAMNLS4KKAN", "THEFESTIV4LLET")))
for c, p in c2p.items():
    # a monoalphabetic substitution is a bijection:
    # two cipher letters can never share a plaintext letter
    assert all(v != p for k, v in c2p.items() if k != c)

pt = "".join(c2p.get(ch.upper(), "?").lower()
             if ch.isalpha() else ch for ch in ciphertext)
```

```
dear kavitha, here is the line you asked for. thefestiv4llet ter.
read it twice before you send anything upward.
```

```
flag: thefestiv4lletter
```

**Two things to know about this one before you start.**

It does **not** need the keyword. The crib alone plus the `4` alignment is
enough, and frequency analysis would get there too. The keyword derivation
described in the case file and the hint — the letter set of
`PRITHVI/{BAY}-{VOLTAGE}KV/{IED}` from the tender's asset nomenclature —
is a **second, independent path** that the shipped ciphertext does not match.
Building a keyed alphabet from it and testing it against this substitution
reproduces 8 of 21 mappings, so if you follow the hint exactly and get
nothing, the flaw is not yours. Use the crib.

And read the flag carefully where it is printed: the letter breaks it across a
space as `thefestiv4llet ter`. Submit it as
`thefestiv4lletter` with the space removed.
