# KeyPair Entropy Provider (KPEP) for OpenSSL 3.5.x

The KeyPair Entropy Provider (KPEP) is an OpenSSL 3.5.x provider that is designed
to provide robust entropy services to other OpenSSL providers.  KPEP is designed
to be fully compliant with SP 800-90C and has a variety of notable features:

1) Gather from multiple entropy sources; combine according to 800-90C requirements
2) Gracefully handle temporary or permanent failues of entropy sources
3) Built-in [Jitter entropy](https://github.com/smuellerDD/jitterentropy-library) source
4) Built-in support for Intel/AMD RdSeed and RdRand entropy sources
5) Full runtime configuration from OpenSSL configuration file
6) Operate as RBG2 or RBG3 construction
7) Designed to be FIPS 140-3 validated (integrity test, CASTs, ACVP support, etc)
8) Extensible through OS file system (e.g. "/dev/random" or "/dev/acme-hwrand")
9) Extensible through 3rd party shared libraries (provided API and example)

This project started as the KeyPair
Management Provider (KPMP), part of the KeyPair FIPS Provider Plus (KPFP+) solution.

## STATUS

This project/branch is under active development and is on-track for a Release Candidate (RC1).  To be clear, this is very much a **work in progress**.  If you've found your way here, it's because you've been given early access to the work.

In the current form, it is a fully working provider and entropy source, and all of the nine (9) stated features above are implemented and working.  There is a TODO.md file in the root of the project that describes the roadmap to RC1.

Due to scheduling, I have to put the project on hold until mid-November 2026.  Several tasks remain in-flight, notably the error handling and numbering is somewhat a mess at the moment.
