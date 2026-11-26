# ARDent Entropy Provider Seeding Subsystem

The ARDent Entropy Provider replaces OpenSSL's default `SEED-SRC` entropy source. ARDent does not consume entropy independently. It supplies entropy to the OpenSSL request path through its internal DRBG.

The entropy flow is:

```
OpenSSL entropy request
				|
				v
Provider Seed Source API (ardent_seeding.c)
				|
				v
DRBG (crypto/drbg.c)
				|
				v
Seed Controller (seeding/seed_control.c)
				|
				v
Async Seed Source wrapper (seeding/async_seed.c)
				|
				v
Actual seed source (seeding/seed_stub_*.c)
```

The provider-facing seed API and the DRBG form the OpenSSL integration boundary; the Seed Controller and source wrappers implement source selection, policy, and gathering.

## Seeding hierarchy and call tree

### Provider Seed Source API (ardent_seeding.c)

Implements the OpenSSL provider API for the replacement `SEED-SRC`. It receives
entropy requests from OpenSSL and passes them to the DRBG. It also reports the
current seed state and source description to OpenSSL.

Relevant implementation and API locations:

- `source/ardent_seeding.c`
- `include/ardent/ardent.h`
- `include/ardent/ardent_names.h`

### DRBG (crypto/drbg.c)

The HMAC-SHA2-256 DRBG mixes and conditions entropy gathered by the Seed
Controller. It is treated as a black box by the seeding subsystem: its relevant
role here is to be the sole consumer of seed entropy and the component that
requests entropy when it needs it.

Relevant header: `source/crypto/drbg.h`.

### Seed Controller (seeding/seed_control.c)

This is the management layer to coordinate the behavior of the seed sources.  It owns the configured seed-source contexts and enforces source policy regarding availability, failover, and error handling.  

The controller maintains two (2) lists of sources: A list of validated sources used for qualified entropy, and a list of non-validated (non-qualified) sources used for DRBG "additional entropy".

The controller creates one Async Seed Source wrapper for each active source.  At least one (1) validated source is required for initialization.  

Relevant files:

- `source/seeding/seed_control.h`
- `source/seeding/seed_control.c`
- `include/ardent/ardent_seed_stub.h`
- `source/seeding/seed_sources.h`

### Asynchronous Seed Source (seeding/async_seed.c)

The Async Seed Source wrapper combines one actual seed source with a ring buffer
and the synchronization state needed to gather from it. The same wrapper is
used in synchronous mode and asynchronous mode. In asynchronous mode, a worker
thread refills the ring buffer for each active source; in synchronous mode,
gathering blocks while the source is read.

The wrapper exposes a common gathering and state interface to the Seed
Controller, so the controller does not need to know whether the underlying
source is built in, file-backed, or external.

Relevant files:

- `source/seeding/async_seed.h`
- `source/seeding/async_seed.c`
- `source/seeding/ringbuffer.h`

### Seed Sources

Seed sources provide the raw entropy gathered by the Async Seed Source wrapper.
Each source reports its output block size and credited entropy so the wrapper
can determine how much source material is needed for an entropy request.

The source interface is defined by `include/ardent/ardent_seed_stub.h`. The built-in
source definitions and their configuration prefixes are listed in
`source/seeding/seed_sources.h`.

Relevant files:

- `include/ardent/ardent_seed_stub.h`
- `source/seeding/seed_sources.h`

#### Jitter Entropy

The jitter entropy source derives entropy from timing jitter using Jitterentropy,
statically linked into the provider from an externally supplied `libjitterentropy.a`.
It is represented by the `seed.jitter` source configuration and has one instance
per machine. ARDent does not compile or bundle the Jitterentropy implementation;
its archive and headers are build dependencies.

Configure the dependency using exactly one of these forms:

- `-Djitter-source=/path/to/jitterentropy-library` uses a source checkout with a
  prebuilt `libjitterentropy.a` at its root. CMake uses headers from the checkout
  root and its `src/` directory.
- `-Djitter-lib=/path/to/libjitterentropy.a` together with
  `-Djitter-include=/path/to/flat/headers` uses a separately located archive and
  one directory containing all required headers (including
  `jitterentropy.h`, `jitterentropy-base-user.h`, `jitterentropy-sha3.h`, and
  `jitterentropy-internal.h`). The header directory must be flat; CMake does not
  search a `src/` subdirectory in this mode.

The two modes are mutually exclusive, and `jitter-lib` and `jitter-include`
must be supplied together. CMake does not build Jitterentropy. The supplied
archive must be suitable for static linking into the ARDent provider shared
object; compiler and linker diagnostics report archive compatibility issues.

For example, using a checkout:

```sh
cmake -S . -B build -Djitter-source=/path/to/jitterentropy-library
```

Or using a separate archive and flat header directory:

```sh
cmake -S . -B build \
  -Djitter-lib=/path/to/libjitterentropy.a \
  -Djitter-include=/path/to/flat/headers
```

#### Intel/AMD RDSEED

The RDSEED source accesses the CPU instruction exposed by supported Intel and
AMD processors. It is represented by `seed.rdseed` and has one instance per
machine. Availability depends on CPU support.

#### Intel/AMD RDRAND

The RDRAND source accesses the CPU instruction exposed by supported Intel and
AMD processors. It is represented by `seed.rdrand` and has one instance per
machine. Availability depends on CPU support.

#### Operating-system filesystem

The OS source reads entropy through a configured filesystem path. Common
examples are `/dev/random`, `/dev/hwrand`, `/dev/tpm`, and event vendor-specific
devices such as `/dev/acme-entropy`. The important property is the device/file
interface, not a particular operating system or pathname.

The source is represented by `seed.osrand`. Up to four instances can be
configured, using numbered options such as `1.filepath` through `4.filepath`.

#### External

The external source loads a shared object that implements the ARDent seed-source
stub interface. This allows a vendor or integrator to provide a custom source
without changing the provider. Up to four external instances can be configured
through `seed.extseed`.

The required integration points are the shared-object path and the exported
`STUB_FUNCTIONS` symbol. See `include/ardent/ardent_seed_stub.h` for the interface
and `example/external_entropy` for an example implementation. The example wraps
the jitterentropy static library in a lightweight ARDent seed-source
implementation.

## Configurations and Runtime Options

Configuration is supplied through the `seed` section of the OpenSSL provider
configuration. The reference configuration is `resources/ardentmodule.cnf`.
Source parameters use the names defined in `include/ardent/ardent_names.h`.

### Seed source categories

Each source is configured as either validated entropy or additional input:

- `validated`: identifies a source that is qualified for validated entropy. In
	the configuration file this is a validation identifier such as `E239`; an
	active validated source is required.
- `hardware-source`: marks a source as hardware for restricted entropy counting.
	Default: `0`.

The source types `jitter`, `rdseed`, and `rdrand` support one instance each.
The `osrand` and `extseed` source types support up to four instances, selected
with a numeric prefix from `1` through `4`.

### Common source options

The following options apply to source instances:

- `activate`: whether the source is used. Default: `0`.
- `validated`: validation identifier for a qualified source. No default; at
	least one validated source must be configured.
- `hardware-source`: whether the source is treated as hardware for restricted
	entropy counting. Default: `0`.
- `block-size`: source output block size in bits. The configuration must provide
	this for an active source.
- `block-count`: number of output blocks (of the given block size) necessary to
	meet the minimum credited strength (256 bits).  For example, a source with
    "full entropy" and 128 block-size would have a block-count of 2. The
    configuration must provide this for an active source.
- `ring-size`: ring-buffer size in bits for asynchronous operation. It must be a
	power of two. The configured value describes credited entropy capacity; the
	allocated buffer can be larger based on source quality and block settings.

### Source-specific options

- `filepath`: absolute path to a filesystem entropy source or a shared object.
	Required for `osrand` and `extseed` instances.
- `functions`: exported symbol containing the `STUB_FUNCTIONS` function table.
	Required for `extseed` instances.
- `seed.jitter.oversample-rate`: oversample rate for the jitter source. The
	reference configuration default is `4`.
- `retry-count`: number of retries for RDSEED or RDRAND. Ignored by other
	source types.

### Seed pipeline options

- `seed.perso`: device-specific personalization string used when initializing
	the DRBG. It should be unique for each device. The reference configuration
	includes it from `personalization.cnf`.
- `seed.async-mode`: selects asynchronous worker and ring-buffer operation when
	set to `1`. Default: `0`, synchronous operation.
- `seed.req-all-sources`: requires every active source to provide entropy for
	each request when set to `1`. Default: `0`.
- `seed.req-some-sources`: requires at least one source to provide entropy for
	each request when set to `1`. Default: `1`.
- `seed.req-hardware-source`: enables restrictive entropy counting, requiring a
	hardware source to back validated entropy use. Default: `0`.

### Restricted Entropy Counting

When `seed.req-hardware-source` is enabled, the Seed Controller applies the
restricted counting policy to validated sources. Initialization requires at
least one validated hardware source, and readiness requires an eligible
hardware source to remain ready.  Each gather performed by the controller
must sucessfully retrieve entropy from at least one hardware source.

### Async Mode

When `seed.async-mode` is `0` or absent, gathering is synchronous and the
requesting thread waits while source material is gathered. When it is `1`, each
active source has a worker-backed wrapper that maintains a ring buffer so
requests can be served from buffered source material.

Detailed worker lifecycle, ring-buffer behavior, option interactions, testing,
and failure-injection procedures are documented separately or deferred for
later revisions of this document.




