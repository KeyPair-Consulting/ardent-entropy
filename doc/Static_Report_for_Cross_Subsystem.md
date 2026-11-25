# Static Analysis Report — Cross-Subsystem Interaction Candidates

**Status:** Deferred; interaction analysis will begin after all individually scoped subsystem analyses are complete.
**Scope:** This report collates findings that require inspecting or validating more than one subsystem. It does not itself analyze those external subsystems.

## Source: `source/crypto`

1. **Jitterentropy `SHA3_CTX` layout and lifecycle**
   - Previously raised while analyzing `source/crypto/sha3_jent_wrapper.c`.
   - The `sha3_ctx_dup()` concern was removed after `sha3_ctx_dup()` was removed.
   - Dynamic `sha3_oneshot()` allocation should be rechecked against Jitterentropy allocation/free semantics.
   - Relevant crypto code: `source/crypto/sha3_jent_wrapper.c`.

2. **DRBG and seeding interaction**
   - Confirm that `seed_control_gather()` returns buffers and lengths matching DRBG expectations.
   - Confirm entropy and additional-input ownership/lifetime and cleanup semantics.
   - Relevant crypto code: `source/crypto/drbg.c`.
   - External subsystem: `source/seeding`.

3. **OpenSSL parameter and dispatch contracts**
   - Confirm digest/MAC dispatch signatures, parameter getters/setters, context duplication semantics, and result-length behavior.
   - Relevant crypto code: `source/crypto/sha2.c`, `source/crypto/sha3_jent_wrapper.c`, `source/crypto/hmac.c`, and `source/crypto/drbg.c`.

4. **KPEP security-strength and result/error definitions**
   - Confirm the strength constants, request limits, and error-code meanings used by DRBG and provider wrappers.
   - Relevant crypto code: `source/crypto/drbg.h` and `source/crypto/drbg.c`.

## Source: `source/debug`

1. **OpenSSL mutex/thread API**
   - Validate `ossl_crypto_mutex_*` and `ossl_crypto_thread_*` behavior and lifecycle.
   - Relevant debug code: `source/debug/debug_core.c`.

2. **OpenSSL configuration, BIO, and error APIs**
   - Validate `NCONF_*`, `BIO_*`, and `ERR_*` interactions and lifecycle.
   - Relevant debug code: `source/debug/debug_core.c`.

3. **Provider parameter API**
   - Validate `kpep_get_core_params()` and provider parameter constants.
   - Relevant debug code: `source/debug/debug_core.c`.

4. **External profile structure**
   - Validate `SEED_STUB_INFO` layout and synchronization contract.
   - Relevant debug code: `source/debug/kpep_profile.c`.

5. **External debug callers**
   - Callers may invoke trace/profile APIs concurrently or during shutdown/reconfiguration.
   - Relevant declarations: `source/debug/debug_core.h`.

6. **Debug build/configuration dependencies**
   - Debug feature macros, `KPEP_LIB_CFLAGS`, `KPEP_LIB_LDFLAGS`, and OpenSSL compile settings.
   - Relevant build code: `source/debug/CMakeLists.txt`.

## Source: `source/logging`

1. **OpenSSL mutex/thread API**
   - Validate `ossl_crypto_mutex_*` behavior, lifetime, and nested-use behavior.
   - Relevant logging code: `source/logging/kpep_logging.c`.

2. **OpenSSL provider parameter lookup**
   - Validate activation and level parameter loading through `kpep_get_core_params()`.
   - Relevant logging code: `source/logging/kpep_logging.c` and sink parameter loaders.

3. **External shared-library ABI**
   - Validate `SINK_FUNCTIONS` layout and initialization/finalization/function-pointer compatibility.
   - Relevant logging code: `source/logging/sink_extern.c`.

4. **Syslog/system facilities**
   - Validate platform-specific `syslog()` behavior and logging-level mapping.
   - Relevant logging code: `source/logging/sink_syslog.c`.

5. **Trace/logging interaction**
   - Trace calls occur from logging paths while a logging mutex may be held; validate recursion and nested-lifecycle behavior.
   - Relevant logging code: `source/logging/kpep_logging.c` and sink implementations.

6. **KPEP allocator contracts**
   - Validate ownership and failure behavior for `kpep_zalloc()`, `kpep_free()`, and `kpep_cleanse()`.
   - Relevant logging code: binary sink formatting and external/provider lifecycle paths.

7. **Provider initialization/finalization lifecycle**
   - Validate repeated init/fini behavior and provider unload ordering.
   - Relevant logging code: `source/logging/kpep_logging.c` and provider lifecycle callers.

## Collation Notes

- Subsystem-specific findings remain in their respective reports.
- Cross-subsystem candidates are maintained centrally in this file.
- When future prompts resolve or add interaction findings, update this file rather than reintroducing them into subsystem reports.
- Do not begin interaction analysis until explicitly requested to do so.
