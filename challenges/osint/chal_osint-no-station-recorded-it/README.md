# SIM-01 -- No Station Recorded It

**Act I · OSINT · Easy**

## The brief

A public rainfall and outage advisory feed has been falsified.
Somebody with routine write access used it, in August, to publish a line that
does not belong there. SANDVIPER left one error in every bundle they copied
out. Find it.

## What you must do

Determine which advisory was falsified and recover the message
embedded in it. registry/ holds the station registry; press/ holds real IMD
2025 monsoon figures retained for correlation; the feed is in feed/.

## Getting started

Work through the `artifacts/` directory. Everything you need is there; nothing needs to be running.

```console
unzip vec-SIM-01-player.zip -d SIM-01
cd SIM-01/artifacts && ls
```

## Hints

No hint files are published: a reveal costs 3 of the 5 points, so the hint
stays with the organiser. Read the briefing twice before asking.

## Rules

* Attack only this lab. Do not touch infrastructure that is not yours.
* Every instance has its own flag. Do not publish flags; publish your method.
* All organisations, software and incidents here are fictional.
