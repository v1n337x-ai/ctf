# Privilege escalation

6 challenges in this category.

Active Directory and Linux: ACLs, delegation, password history and replication rights.

## Before you start

Most of these are enumeration problems rather than exploit problems. The interesting part is usually noticing that a permission is broader than the person who granted it intended. Read the hint before you start - several of these are about a configuration that is perfectly reasonable in isolation.

## Challenges

| ID | Name | Flaw | Status |
|---|---|---|---|
| `SIM-27` | Kharga | ACL enumeration | approach below |
| `SIM-28` | NOPASSWD | Over-broad sudo rule | approach below |
| `SIM-29` | Krbtgt | Password reuse / history | approach below |
| `SIM-30` | Cross Domain | Unsigned update agent | approach below |
| `SIM-31` | DCSync | Over-broad replication right | approach below |
| `SIM-36` | The Finale | Ordered challenge chain | approach below |

---

## Approaches

### SIM-27 - Kharga

**Flaw.** ACL enumeration

The 'lockdown' is an access control list, and ACLs are readable from inside by anyone who has logged in. Enumerate it first. The overnight backup task runs a file this domain logon can write, which is the other half.

**No published write-up for this one.** The solve was not verified before publication and a wrong offset in a memory corruption exploit is worse than no write-up at all - it fails and convinces you the challenge is broken.

### SIM-28 - NOPASSWD

**Flaw.** Over-broad sudo rule

The sudo rule is not the bug -- it is a NOPASSWD rule for one helper, which is a deliberate and legitimate configuration. Read what that helper sources, and ask who can write to the directory it reads from.

**No published write-up for this one.** The solve was not verified before publication and a wrong offset in a memory corruption exploit is worse than no write-up at all - it fails and convinces you the challenge is broken.

### SIM-29 - Krbtgt

**Flaw.** Password reuse / history

Two facts do the work. `krbtgt` password history is 2, so the old value stays recoverable until it is reset twice with a gap at least as long as the maximum ticket lifetime -- and guidance requires that reset at least every 180 days. Separately, service tickets in RC4 (etype 23) crack roughly a thousand times faster than the AES types. Ask the directory for a ticket, then crack it.

**No published write-up for this one.** The solve was not verified before publication and a wrong offset in a memory corruption exploit is worse than no write-up at all - it fails and convinces you the challenge is broken.

### SIM-30 - Cross Domain

**Flaw.** Unsigned update agent

The conduit agent checks the *version* of what it is handed. It does not check the trust of what is handing it. Ask where the update payload is fetched from, and whether that source is verified at all -- then ask where the agent can be made to load something of yours.

**No published write-up for this one.** The solve was not verified before publication and a wrong offset in a memory corruption exploit is worse than no write-up at all - it fails and convinces you the challenge is broken.

### SIM-31 - DCSync

**Flaw.** Over-broad replication right

No exploit is involved. Domain Admin needs one replication right granted to an ordinary principal, and the protocol is not broken -- the ACL is wrong. Ask what rights this account's ACL carries, and read the documentation string in the source for which operations require which rights.

**No published write-up for this one.** The solve was not verified before publication and a wrong offset in a memory corruption exploit is worse than no write-up at all - it fails and convinces you the challenge is broken.

### SIM-36 - The Finale

**Flaw.** Ordered challenge chain

The finale. The console accepts proofs in order and only in order, and the eight Master Shards are the flags of eight other challenges. The agent that fronts the console runs as a service with a writable library path, so reaching the console is one substitution away. Solve the other eight first.

**No published write-up for this one.** The solve was not verified before publication and a wrong offset in a memory corruption exploit is worse than no write-up at all - it fails and convinces you the challenge is broken.

