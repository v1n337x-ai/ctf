# SIM-21 -- BYOVD

**Act IV · Reverse Engineering · Hard**

## The brief

The ground systems talk to their sensors through a kernel driver.
This one also seals its own control channel. A driver has no userland to hide
in.

## What you must do

Recover the IOCTL channel key from the driver binary.

## Getting started

Work through the `artifacts/` directory. Everything you need is there; nothing needs to be running.

```console
unzip vec-SIM-21-player.zip -d SIM-21
cd SIM-21/artifacts && ls
```

## Hints

No hint files are published: a reveal costs 3 of the 5 points, so the hint
stays with the organiser. Read the briefing twice before asking.

## Rules

* Attack only this lab. Do not touch infrastructure that is not yours.
* Every instance has its own flag. Do not publish flags; publish your method.
* All organisations, software and incidents here are fictional.
