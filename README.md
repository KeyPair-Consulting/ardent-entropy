# ARDent Entropy Provider for OpenSSL

The ARDent Entropy Provider (ARDent) is an OpenSSL 3.5.x provider that is designed
to provide robust entropy services to other OpenSSL providers.  ARDent is designed
to be fully compliant with SP 800-90C and has a variety of notable features:

1) Gather from multiple entropy sources; combine according to 800-90C requirements
2) Gracefully handle temporary or permanent failues of entropy sources
3) Built-in support for [Jitter entropy](https://github.com/smuellerDD/jitterentropy-library) source, linked from an externally supplied static archive
4) Built-in support for Intel/AMD RdSeed and RdRand entropy sources
5) Full runtime configuration from OpenSSL configuration file
6) Operate as RBG2 or RBG3 construction
7) Designed to be FIPS 140-3 validated (integrity test, CASTs, ACVP support, etc)
8) Extensible through OS file system (e.g. "/dev/random" or "/dev/acme-hwrand")
9) Extensible through 3rd party shared libraries (provided API and example)

This project began as the KeyPair Management Provider (KPMP), part of the KeyPair FIPS Provider Plus (KPFP+) solution.

## STATUS

This project/branch is under active development and is on-track for a Release Candidate (RC1).  To be clear, this is very much a **work in progress**.  If you've found your way here, it's because you've been given early access to the work.

In the current form, it is a fully working provider and entropy source, and all of the nine (9) stated features above are implemented and working.  There is a TODO.md file in the root of the project that describes the roadmap to RC1.

The current timeline is to release RC1 by Dec 31, 2026. Release of 1.0.0 will be follow the release of the stable OpenSSL 4.x version intended for FIPS 140-3 validation.
