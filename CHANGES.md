# KeyPair Entropy Provider (KPEP) Change Log

This file contains an overview of all changes contained in each release version.

## Current Status

The current status is "In development", version: 0.0.1-dev.

## Revision History

### Development 0.0.2

Imported changes from "rss-async" breanch of KPMP.  

* Adds locking for seed source in kpep_seeding.c
* Creates a new abstraction layer called "aysnc_ringbuffer" which ties a ringbuffer impl with a seed source.  File seed_control.c now handles these instead of direct control of seed sources.  Although designed for Asynchronous operation, currently synchronous operation only.

### Development 0.0.1

First revision, freshly branched from KPMP
