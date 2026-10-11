# SIM-14 -- Six Bytes Per Ping

**Act II · Reverse Engineering · Medium**

## The brief

A coastal monitoring station logged its overnight pings and then
stopped answering. The instrument writes a vendor container called TLM1, and
the vendor's field reference for that container shipped with the download.

## What you must do

Recover the channel recorded across the night's pings from
capture/ping_log.tlm.

## Getting started

Work through the `artifacts/` directory. Everything you need is there; nothing needs to be running.

```console
unzip vec-SIM-14-player.zip -d SIM-14
cd SIM-14/artifacts && ls
```

## Hints

No hint files are published: a reveal costs 3 of the 5 points, so the hint
stays with the organiser. Read the briefing twice before asking.

## Rules

* Attack only this lab. Do not touch infrastructure that is not yours.
* Every instance has its own flag. Do not publish flags; publish your method.
* All organisations, software and incidents here are fictional.
