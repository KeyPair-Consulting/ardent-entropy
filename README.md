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

## BUILDING

ARDent requires CMake, a compatible OpenSSL 3.5.x installation, and a prebuilt
Jitterentropy static archive. 

### OpenSSL

ARDent installs itself into OpenSSL and needs information about the target environment.  Supply one of these configurations:

- `-DOPENSSL_ROOT=/path/to/openssl` to derive all OpenSSL directories; or
- `-DOPENSSL_SSLDIR`, `-DOPENSSL_BINDIR`, `-DOPENSSL_LIBDIR`, and
  `-DOPENSSL_MODULES` for fully explicit directories.

The `OPENSSL_ROOT` directory is the equivalent to the `--prefix` directory argument used for building OpenSSL.  This root directory is expected to have children `bin/`, `lib[64]/`, and `ssl/`.  CMake will derive the 4 directories from the specified root.  

Alternatively, explicit directory arguments override corresponding values derived from `OPENSSL_ROOT`. The following defaults are used:

- `OPENSSL_SSLDIR` defaults to `OPENSSL_ROOT/ssl` and contains the configuration files.
- `OPENSSL_BINDIR` defaults to `OPENSSL_ROOT/bin` and contains the binary applications.
- `OPENSSL_LIBDIR` defaults to `OPENSSL_ROOT/lib[64]`, depending on environment, and containing the `libcrypto` and `libssl` libraries.
- `OPENSSL_MODULES` defaults to `OPENSSL_LIBDIR/ossl-modules` and contains the providers

CMake fails configuration if any of the four resolved directories is unknown.

For example, using an OpenSSL installation root:

```sh
-DOPENSSL_ROOT=/path/to/openssl
```

Or specifying all four directories explicitly:

```sh
-DOPENSSL_LIBDIR=/path/to/openssl/lib64 \
-DOPENSSL_BINDIR=/path/to/openssl/bin \
-DOPENSSL_SSLDIR=/path/to/openssl/ssl \
-DOPENSSL_MODULES=/path/to/openssl/lib64/ossl-modules
```

### Jitter Entropy

ARDent requires a Jitter Entropy to be available to statically compile into the provider shared object.  Users can specify the location of the library archive and headers in one of two ways:

Use `jitter-source=` when you are specifying the location of the project source including code, headers, built libraries, etc.

```sh
-Djitter-source=/path/to/jitterentropy-library
```

Or configure it with a separate Jitterentropy archive and flat header directory:

```sh
-Djitter-lib=/path/to/libjitterentropy.a \
-Djitter-include=/path/to/flat/headers
```

The header directory must contain:

- `jitterentropy.h`
- `jitterentropy-base-user.h`
- `jitterentropy-sha3.h`
- `jitterentropy-internal.h`

CMake does not build Jitterentropy. The specified archive and headers must be compatible with the target platform and compiler.

### Examples

The complete configuration and build commands are:

```sh
cmake -S . -B build \
  -DOPENSSL_ROOT=/path/to/openssl \
  -Djitter-source=/path/to/jitterentropy-library
cmake --build build --parallel
```

```sh
cmake -S . -B build \
  -DOPENSSL_LIBDIR=/path/to/openssl/lib64 \
  -DOPENSSL_BINDIR=/path/to/openssl/bin \
  -DOPENSSL_SSLDIR=/path/to/openssl/ssl \
  -DOPENSSL_MODULES=/path/to/openssl/lib64/ossl-modules \
  -Djitter-lib=/path/to/libjitterentropy.a \
  -Djitter-include=/path/to/flat/headers
cmake --build build --parallel
```

The important products of the build process are:

- `ardent.so`, the OpenSSL Provider binary shared object
- `ardentmodule.cnf`, a configuration file containing the runtime settings
- `personalization.cnf`, a configuration file containing a unique per-device string used to instantiate the internal DRBG
- A set of three binary applications:
  - `ardent_rand`, to generate random numbers in several different ways
  - `ardent_utility`, to interact with OpenSSL providers
  - `ardent_debug`, to interact with the ARDent debugging subsystem


## INSTALLING

Install using the paths resolved during CMake configuration:

```sh
cmake --install build
```

The provider is installed in `OPENSSL_MODULES`, utilities in `OPENSSL_BINDIR`, and configuration files in `OPENSSL_SSLDIR`.

After the CMake installation targets are copied, CMake executes `resources/cmake_finalize_ardent.sh` automatically. The finalization script receives the resolved OpenSSL directories and uses `ardent_utility` to generate an HMAC integrity file `ardent.so.mac`, updates the configuration file references for that integrity file and the personalization file, and completes the provider installation.

There is a second script file, `resources/standalone_finalize_ardent.sh`, that contains all the finalization steps without CMake integration.  This script can be harvested for implementation details when these finalization steps need to be performed by an alternate installation process.
