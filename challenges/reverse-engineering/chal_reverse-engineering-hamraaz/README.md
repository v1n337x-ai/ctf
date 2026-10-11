# SIM-20 -- Hamraaz

**Act IV · Reverse Engineering · Medium**

## The brief

The field-verification app district officers use, offline, on bad
links, on cheap handsets. It ships with a credential store and an integrity
check, and the integrity check is the most important line of code in the file.

## What you must do

Defeat the integrity check and dump the local credential
store.

## Getting started

Work through the `artifacts/` directory. Everything you need is there; nothing needs to be running.

```console
unzip vec-SIM-20-player.zip -d SIM-20
cd SIM-20/artifacts && ls
```

## Hints

No hint files are published: a reveal costs 3 of the 5 points, so the hint
stays with the organiser. Read the briefing twice before asking.

## Rules

* Attack only this lab. Do not touch infrastructure that is not yours.
* Every instance has its own flag. Do not publish flags; publish your method.
* All organisations, software and incidents here are fictional.
