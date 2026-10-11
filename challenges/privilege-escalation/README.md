# Privilege escalation

6 challenges. These are **enumeration** problems, not exploit problems. Almost
none of them need a shell you did not have — they need you to read a permission
more carefully than the person who granted it did.

That is the through-line. Every challenge here has a configuration that looks
entirely reasonable in isolation and is wrong in combination.

## Before you start

These run as Python services that simulate directory and host state. There is
no domain to join and no kernel to exploit. Read the source — it is short, it
is honest about where the flaw is, and the comment above each vulnerable block
usually names the mistake.

```console
$ cd challenges/privilege-escalation/chal_boot2root-dcsync
$ ./run.sh
```

## How these are graded

Each challenge checks one specific piece of evidence — an ACL value, a sudo
rule, a replication right — against the per-instance objective the flag server
issued. You are not proving you got a shell. You are proving you read the
permission correctly.

---

## SIM-31 — DCSync
### Over-broad replication right

No exploit is involved. The protocol is not broken.

Domain Admin needs exactly two replication rights: `DS-Replication-Get-Changes`
and `DS-Replication-Get-Changes-All`. Grant either one to an ordinary
principal and that principal can dump the directory, because the protocol
cannot tell an intended administrator from an unintended one.

The challenge grants one of the two. Find the ACL entry that has it, and submit
the value.

**Why it matters.** This is the single most common real-world Active Directory
misconfiguration. It looks like a narrow, harmless read right, and it is
equivalent to a full domain compromise.

---

## SIM-29 — Krbtgt
### Password history

Two facts do all the work:

- `krbtgt`'s password history is 2, so the previous value is still recoverable.
- It stays recoverable until the password is reset **twice**, with a gap at
  least as long as the maximum ticket lifetime between the resets.

So if the account has only been reset once, the old password is still valid
somewhere — in a snapshot, a backup, or a ticket that was minted before the
reset.

Find the history depth in the challenge state, then work out whether the
window has closed.

> The subtlety teams miss: resetting `krbtgt` once does *not* invalidate the
> old credential in every case. Two resets, correctly spaced, is the actual
> remediation. One reset leaves you exposed.

---

## SIM-28 — NOPASSWD
### Over-broad sudo helper

The sudo rule is not the bug. A NOPASSWD rule for one helper is a deliberate
and legitimate configuration — that is what sudo rules are for.

The bug is in **the helper's source**. Read what it does, and what it lets you
do with the arguments it accepts. A helper that shells out to another command
without validating its arguments is a root shell with extra steps.

The README hint on this one is unusually direct: *the sudo rule is not the bug,
it is a NOPASSWD rule for one helper, which is a deliberate and legitimate
configuration.*

That is the whole lesson. "The sudoers entry looks fine" is a conclusion you
reach before reading the thing it points at.

---

## SIM-27 — Kharga
### ACL enumeration, then a scheduled task

Two steps, and the first is not optional.

The "lockdown" is an access control list, and **ACLs are readable from inside by
anyone who has logged in**. You do not need to escalate to enumerate them; you
need to ask.

Once you have the list, find the overnight backup task and what it can reach.
The task runs with more privilege than you do. The chain is: read the ACL, find
the task, find what the task can read that you cannot.

**Why it matters.** Privilege escalation is very often just "who else can read
this". Most ACL problems are enumeration problems wearing a disguise.

---

## SIM-30 — Cross Domain
### Unsigned update agent

The conduit agent checks the **version** of what it is handed. It does not
check the **trust** of what is handing it to it.

So the version check passes and the signature check is missing entirely. Find
where the agent fetches the update payload from, and serve it something with a
version it will accept.

That is the bug in one sentence: *validating the version of an update without
validating the source of the update is not a version check.*

> This is why "is the update current?" is never a security control on its own.
> An attacker who controls the endpoint controls the version.

---

## SIM-36 — The Vault
### The finale

The console accepts proofs **in order**, and only in order. The eight Master
Shards are the flags of eight other challenges.

So this is not a new technique — it is a checkpoint. Solve eight others, bring
their flags, and submit them as an ordered sequence.

It is rated Insane because of the coordination, not the difficulty. If you are
attempting it solo, solve the other categories first and keep your flags
somewhere you can read them in order.

**A note on verification.** This write-up describes the intended path. The
finale depends on flags from challenges whose solutions were verified
individually, so submitting them in order is expected to work, but the sequence
itself was not run end to end here.
