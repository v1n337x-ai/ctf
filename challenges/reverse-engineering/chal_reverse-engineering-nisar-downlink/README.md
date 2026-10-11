# SIM-22 -- NISAR Downlink

**Act IV · Reverse Engineering · Hard**

## The brief

Ground-station firmware boots in two stages and refuses to boot a
stage two it cannot verify. The old slot on every station is still signed, by a
key that is still in the chain. Nobody rotated it.

## What you must do

Bypass the boot verification and reach the previous firmware
slot.

## Getting started

Work through the `artifacts/` directory. Everything you need is there; nothing needs to be running.

```console
unzip vec-SIM-22-player.zip -d SIM-22
cd SIM-22/artifacts && ls
```

## Hints

No hint files are published: a reveal costs 3 of the 5 points, so the hint
stays with the organiser. Read the briefing twice before asking.

## Rules

* Attack only this lab. Do not touch infrastructure that is not yours.
* Every instance has its own flag. Do not publish flags; publish your method.
* All organisations, software and incidents here are fictional.
