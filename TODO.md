# TODO List before completion

Task IDs are stable references; priority sections may be reorganized without changing IDs. 

## Minor / Features and Fix-up

### SEED-STATE — Better state handling from bottom to top

- Implement ready vs not-ready vs error.
- Ignore sources in error state.
- Handle source degradation (e.g. max gather retry).

- **Status:** Design and error-propagation work were discussed and partially implemented; current end-to-end status needs review.
- **Next:** Trace current source → async wrapper → seed control → DRBG state/error behavior, then identify missing cases and add focused tests.

### SEED-ENTROPY-ROUTING — Test all 3 methods of entropy for routing to KPEP

- **Status:** Pending; no test completion recorded here.
- **Next:** Identify the three supported routing methods and their expected inputs/outputs, then create a test matrix for each.

### SEED-LOG-CONTEXT — Turn seeding and logging into context objects, not singletons

- **Status:** Pending; architectural change.
- **Next:** Map singleton state, ownership, and lifecycle first; propose a migration plan before changing code.

## Major / Structural

### DBG-WIN-IPC — Validate and harden Windows debug IPC support

- Validate build on Windows.
- Build and runtime-test `keypair_debug` against named pipes.
- Verify `OPENSSL_CONF` representation of named-pipe paths.
- Add busy-pipe retry and improve Windows error reporting.

- **Status:** Windows named-pipe support is implemented but remains functionally—not strictly—validated; build/runtime validation and hardening are pending.
- **Next:** Establish a Windows build/runtime test environment; verify path parsing and named-pipe connection behavior, then implement retry/error improvements and test them.

### PROF-RUNTIME-IPC — Implement profiling runtime communications

- Create a thin abstraction layer for POSIX/WINDOWS (`kpep_shm.c` and `kpep_event.c`).
- SHM for the data plane.
- Signaling for wakeup.
- Shared object for client-side use: accept callback pointers, start profiling with config, monitor events, and signal callbacks with data.
- Example application that uses the shared object.

- **Status:** Architecture discussed; implementation pending.
- **Next:** Refine the protocol and lifecycle/API boundaries, then plan a minimal cross-platform SHM/event prototype and its tests.

### SEED-ASYNC-GATHER — Implement async gather in all `async_seed.c` paths

- **Status:** Partial async/sync infrastructure exists; completing async gather across paths remains pending.
- **Next:** Inventory all `async_seed.c` gather paths and source wrappers; document which paths gather synchronously versus via worker, then complete and test the missing async paths.

## Optional

### RING-MODULE-WRAP — Change ringbuffer to modulo wrap detection; remove power-of-two requirement

The power-of-two requirement is fine for small buffers, but might force overly-large allocations on some systems.  For example, on some AMD-based systems, RdSeed may need to gather 90K+ bits to meet the 256-bit qualified entropy minimum.  If an admin wants the ring buffer to store 4x gathers, that's 360K+ bits, which have to get rounded to 512K bits to meet the power-of-two requirement.

- **Status:** Pending design/implementation decision.
- **Next:** Compare wrap-detection options against current capacity/index invariants; benchmark the chosen approach before removing the power-of-two constraint.

### TRACE-SEED-END — Add `TRACE_END` to all seed paths

Currently, the tracing records the entry to each critical function of the seed path.  This would add a matched exit record, and implement to indentation scheme to aid navigation.  

This is actually a big change because it requires a structural change to each affected function.  Those functions would have to be restructured to never exit early, but instead have a single exit point with tracing.  

- **Status:** Pending audit/completion.
- **Next:** Find seed functions that emit `TRACE_START` without a matching `TRACE_END`; ensure every return path is covered, preferably through a common cleanup path where appropriate.

### CPUINFO-PORTABILITY — Update CPUINFO

The detection we have works under all conditions we've tested, and we don't require any more functionality in this area.  But it's based on an older and less sophisticated method than some current implementations.

Gaining access to OpenSSL's API would be the least impactful way to upgrade.  This is a change on their part that would provide wider benefit to the community, and should be recommended to OTC.  There are OSS libraries like Google's `cpu_info` project, but they all add code for limited to no benefit.

- **Status:** Alternatives noted; no implementation plan approved.
- **Next:** Reassess the current CPU feature-detection requirements and portability constraints, then compare approaches before selecting one.

## Finalization

Complete these checks before each release.

### RELEASE-ERROR-STRINGS — Verify error strings

- **Status:** Required each release.
- **Next:** Review registered error reasons and confirm messages are accurate and covered by the release build.

### RELEASE-VERSION-NUMBERS — Verify version numbers

- **Status:** Required each release.
- **Next:** Check project/provider version declarations and release metadata for consistency.
