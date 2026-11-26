# Static Analysis Report — `source/logging`

**Status:** Deferred; no subsystem fixes are in progress.
**Scope:** Only `/home/dev/code/KeyPair/ardent/source/logging`.
**Build/lint result:** VS Code diagnostic scan found no errors in `source/logging`.

## Deferred Findings

### 1. High — Logging mutex uses unsynchronized lazy initialization

**Locations:**
- `source/logging/ardent_logging.c:69-75`
- `source/logging/ardent_logging.c:174-175`

**Evidence:**
`ardent_log_lock()` and `ardent_logging_init()` initialize `log_mutex` lazily without synchronization. `ardent_logging_fini()` does not free the mutex.

**Risk:**
Concurrent first use can create separate mutex instances, lose synchronization, or race on pointer assignment. A permanently retained mutex can also leave lifecycle cleanup incomplete.

**Resume direction:**
- Initialize `log_mutex` eagerly once during subsystem initialization, or use synchronized one-time initialization.
- Free the mutex during finalized/shutdown lifecycle only after all logging users and sink operations stop.
- Ensure every lock and unlock path is paired and the mutex cannot be replaced while in use.

### 2. High — Sink registration and shutdown are unsynchronized

**Locations:**
- `source/logging/ardent_logging.c:89-113`
- `source/logging/ardent_logging.c:243-255`
- `source/logging/ardent_logging.c:348-376`

**Evidence:**
`ardent_log_add_sink()` and `ardent_logging_fini()` mutate `sinks[]` directly. The logging mutex is used for writes, but it is not used by registration or finalization.

**Risk:**
Concurrent logging can observe sink registration/removal while pointers are changing, leading to inconsistent lifetime, use-after-free, or use-after-unload behavior.

**Resume direction:**
- Lock sink-table registration, mutation, finalization, and writes under one consistent synchronization mechanism.
- Preserve sink lifetime until all active writes complete.
- Define and test repeated init/fini behavior.

### 3. High — Sink description formatting is broken

**Location:**
- `source/logging/ardent_logging.c:260-269`

**Evidence:**
`ardent_get_sink_descs()` calls `sprintf()` without an output buffer argument:

```c
sprintf("  Name: %-12s Lvl: %-12s\n",
        sinks[idx].name,
        get_log_level_string(...));
```

**Risk:**
This is invalid function use and can cause a compiler diagnostic or undefined behavior depending on the declaration/signature and strict compilation settings.

**Resume direction:**
- Change the function to receive and validate a real buffer and size.
- Produce bounded output with `snprintf()` and report required length or truncation.
- Define whether the function appends or rewrites the complete description.

### 4. Medium — External sink contract is only partially validated

**Locations:**
- `source/logging/sink_extern.c:144-172`
- `source/logging/sink_extern.c:221-226`

**Evidence:**
The external library is represented by `SINK_FUNCTIONS`, but initialization and later access do not validate all of `ext_sink`'s required function pointers before calls.

**Risk:**
A malformed or incompatible shared object can crash during external-sink initialization or logging.

**Resume direction:**
- Validate `ext_sink != NULL` and every required function pointer before initialization or registration.
- Check the external ABI/version if available.
- Reject the sink cleanly on any missing contract element.

### 5. Medium — External sink shutdown and library lifetime are unsafe

**Locations:**
- `source/logging/sink_extern.c:134-139`
- `source/logging/sink_extern.c:174-181`
- `source/logging/sink_extern.c:221-226`

**Evidence:**
`fini_log_extern()` calls `ext_sink->fini_fn()` without validating the external structure. It does not close `hnd` or clear `ext_sink`, `hnd`, or `filename` on shutdown.

**Risk:**
Shutdown can call a stale pointer or leave loaded-library state attached after finalization. A later logging or initialization call can observe stale values.

**Resume direction:**
- Serialize external-sink finalization against writes.
- Validate required pointers and calls.
- Close `hnd` only after the sink and all writes are gone.
- Clear external sink state consistently on success and failure.

### 6. Medium — Binary sink formatting has integer and allocation-size risks

**Locations:**
- `source/logging/sink_stderr.c:101-143`
- `source/logging/sink_syslog.c:95-137`

**Evidence:**
Both sinks calculate:

```c
idx = 14 + (bytes_len * 2);
```

and then add `module` and `label` lengths. `bytes_len * 2` can overflow `size_t`; the prefix and label can make the allocation insufficient or the arithmetic wrap.

**Risk:**
Small allocation or buffer overflow, process crash, corruption, or truncated binary output.

**Resume direction:**
- Check `bytes_len > (SIZE_MAX - fixed_prefix) / 2` and other arithmetic overflow.
- Calculate required lengths with overflow-safe helpers.
- Consider bounded streaming output rather than allocating a full hex string.

### 7. Medium — Unchecked `sprintf()` can corrupt sink formatting

**Locations:**
- `source/logging/sink_stderr.c:118-140`
- `source/logging/sink_syslog.c:112-134`

**Evidence:**
The binary sinks use unchecked `sprintf()` to build fixed-size allocated buffers and derive later offsets from `strlen(msg)` or loop indexes. Bounds are not validated against the actual allocation size.

**Risk:**
Buffer overflow or truncation if module/label text or exact generated text differs from the allocated estimate.

**Resume direction:**
- Replace unchecked writes with `snprintf()` or a bounded output helper.
- Track remaining buffer size rather than relying on `strlen()` after writes.
- Add explicit overflow checks for each generated field.

### 8. Medium — Sink configuration globals are mutable and unsynchronized

**Locations:**
- `source/logging/sink_stderr.c:31,38-65`
- `source/logging/sink_syslog.c:31,38-65`
- `source/logging/sink_extern.c:47-60,64-97`

**Evidence:**
Static `current_log_level`, external `filepath`, `functions`, and external level variables are modified by parameter/environment loading while sink getters/writers may read them.

**Risk:**
Data races and inconsistent configuration snapshots during reload or repeated initialization.

**Resume direction:**
- Serialize configuration reload with sink reads/writes.
- Use immutable snapshot replacement where practical.
- Reset state explicitly and consistently during init/fini.

### 9. Low — Activation flags remain stale across repeated initialization

**Locations:**
- `source/logging/ardent_logging.c:279-330`

**Evidence:**
`activate_syslog`, `activate_stderr`, and `activate_extern` are not reset before a repeated parameter/environment load.

**Risk:**
Later initialization can keep or change activation state based on stale values, especially when provider parameters or environment variables omit a previously set option.

**Resume direction:**
- Reset activation flags to a known default at the beginning of each configuration load.
- Re-evaluate activation precedence across environment and provider configuration.
- Test repeated init/reload paths.

### 10. Low — Partial logging initialization leaves sinks active

**Locations:**
- `source/logging/ardent_logging.c:204-236`
- `source/logging/ardent_logging.c:243-255`

**Evidence:**
If one sink initializes and registers successfully and a later sink fails, `ardent_logging_init()` returns an error without explicitly finalizing or removing earlier registered sinks.

**Risk:**
A failed initialization may leave a partially configured logging subsystem and resources that remain active or duplicate on retry.

**Resume direction:**
- Roll back already initialized sinks on init failure.
- Make initialization atomic: commit registrations only after all required sinks succeed, or document partial success behavior.
- Ensure repeated initialization cannot duplicate sink entries.

## Resume Checklist

1. Re-read the current contents of `source/logging/` before editing.
2. Re-run VS Code diagnostics and the relevant build/test targets.
3. Recheck every finding against any changes made after this report.
4. Review synchronization and lifecycle in a complete init/write/fini sequence before proposing fixes.
5. Investigate external-sink ABI and shared-object cleanup only if explicitly directed.
6. Do not modify code unless a specific issue is subsequently assigned for implementation.
