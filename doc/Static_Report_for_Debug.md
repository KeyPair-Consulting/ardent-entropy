# Static Analysis Report — `source/debug`

**Status:** Deferred; no subsystem fixes are in progress.
**Scope:** Only `/home/dev/code/KeyPair/ardent/source/debug`.
**Build/lint result:** VS Code diagnostic scan found no errors in `source/debug` before the Windows monotonic-clock update.

## Deferred Findings

### 1. High — Lazy mutex initialization races

**Locations:**
- `source/debug/debug_core.c:97-115`
- `source/debug/debug_core.c:777-783`

**Evidence:**
`debug_core_mutex`, `debug_reload_mutex`, and `debug_listener_mutex` use unsynchronized initialization checks followed by mutex allocation.

**Risk:**
Concurrent first users can race, overwrite mutex pointers, or observe an uninitialized/shared state.

**Resume direction:**
- Initialize mutexes eagerly during subsystem initialization.
- Alternatively, use a once/one-time initialization primitive.
- Ensure no mutex is freed while another thread can enter its initialization path.

### 2. High — Sink destruction can race with active writes

**Locations:**
- `source/debug/debug_core.c:145-163`
- `source/debug/debug_core.c:229-273`
- `source/debug/debug_core.c:276-292`
- `source/debug/ardent_trace.c:83-118`
- `source/debug/ardent_profile.c:50-95`

**Evidence:**
Sink release/destroy closes streams and frees the sink lock while trace/profile reload or other users may still hold or use the sink. Writes do not establish a separate lifetime reference.

**Risk:**
Use-after-free, use-after-close, and mutex lock/destroy races.

**Resume direction:**
- Establish explicit sink lifetime/reference counting.
- Prevent destruction until active writes complete.
- Hold lifetime or reload synchronization across write completion.
- Destroy streams and mutexes only after all users exit.

### 3. High — Trace/profile lifecycle state is unsynchronized

**Locations:**
- `source/debug/ardent_trace.c:68-74,93-166`
- `source/debug/ardent_profile.c:38-45,70-177`

**Evidence:**
Trace/profile pointers and enabled flags can be changed during reload or shutdown while readers and writers access them.

**Risk:**
Data races and pointer lifetime races.

**Resume direction:**
- Serialize init/fini/reload with all state reads.
- Use synchronized state snapshots or read/write lifetime protection.
- Make enabled-state changes atomic relative to caller operations.

### 4. High — Profile counters permit lost concurrent updates

**Location:**
- `source/debug/ardent_profile.c:132-177`

**Evidence:**
`seed_stub_profile_update()` increments counters and recalculates/reset state without synchronization of `SEED_STUB_INFO`.

**Risk:**
Lost increments, incorrect averages, and reset/update races.

**Resume direction:**
- Add per-profile-record synchronization.
- Define whether updates and reset operations may overlap.
- Ensure reset and update are serialized or otherwise mutually exclusive.

### 5. Medium — Error deduplication cache is unsynchronized

**Locations:**
- `source/debug/debug_utility.c:223-225,239-248`

**Evidence:**
Static `last_tag` and `last_msg` are read and updated concurrently without synchronization.

**Risk:**
Data races, corrupted cache strings, and nondeterministic duplicate-suppression behavior.

**Resume direction:**
- Protect the cache with the appropriate mutex.
- Alternatively remove cross-thread deduplication.
- Define behavior while logging fallback code is in use.

### 6. Medium — Unix socket setup changes process-wide `umask`

**Location:**
- `source/debug/debug_core.c:738-751`

**Evidence:**
Unix socket setup changes `umask` and restores it afterward.

**Risk:**
A process-wide `umask` change can affect unrelated threads during bind/listen setup.

**Resume direction:**
- Prefer setting final socket permissions after binding/listening.
- If `umask` must remain, synchronize all process-wide `umask` use and document that constraint.

### 7. Medium — Profile output failures are not consistently handled

**Locations:**
- `source/debug/ardent_profile.c:91-129`

**Evidence:**
Profile header and line write results are largely ignored. Profiling can remain marked enabled after output failures.

**Risk:**
The subsystem can report profiling active while output is failing or incomplete.

**Resume direction:**
- Check header and line write results.
- Disable profiling consistently after persistent failure.
- Report failures using the same conventions as trace logging.

### 8. Low/Medium — Diagnostic formatting can silently truncate

**Locations:**
- `source/debug/ardent_trace.c:145-163`
- `source/debug/ardent_profile.c:110-129`

**Evidence:**
Fixed-formatting buffers are used, and positive `vsnprintf`/`snprintf` truncation may not be detected.

**Risk:**
Incomplete or misleading diagnostic records.

**Resume direction:**
- Detect positive truncation results.
- Dynamically size buffers or explicitly report truncation.
- Document maximum names/module/message lengths.

### 9. Low/Medium — Windows monotonic-clock conversion overflow

**Current location:**
- `source/debug/debug_utility.c`, function `ardent_debug_monotonic_us()`

**Original evidence:**
The original expression multiplies the QPC tick count by `1000000ULL` before dividing by the frequency:

```c
(count.QuadPart * 1000000ULL) / freq.QuadPart
```

**Implementation discussion:**
- The original expression can overflow a 64-bit unsigned integer before division.
- The previous attempted fix was rejected.
- A desired approach is to avoid integer multiplication overflow while remaining sufficiently portable.
- The most defensible implementation currently is quotient/remainder conversion plus `long double` for the fractional microseconds.
- This implementation should use `freq.QuadPart <= 0` and `count.QuadPart < 0` guards.
- If `whole_seconds > UINT64_MAX / 1000000ULL`, return `UINT64_MAX`.
- Fractional microseconds must be computed as:

```c
((long double)remainder * 1000000.0L) /
(long double)frequency
```

**Status:**
Deferred. No unresolved code change should be assumed applied unless subsequently verified. The most recent implementation attempt was rejected and must not be described as accepted.

**Alternative resume direction:**
- Use quotient/remainder with a 128-bit integer if compiler support is guaranteed.
- Use guarded integer division/multiplication if exact 64-bit integer behavior is required.
- Use `long double` if minor floating-point rounding is acceptable.
- The previous `long double` implementation attempt should not be reapplied until its exact overflow guards and platform behavior are accepted.

## Resume Checklist

1. Re-read the current contents of `source/debug/` before editing.
2. Re-run diagnostics and relevant builds/tests for `source/debug`.
3. For each deferred item, confirm whether subsequent changes have already altered or resolved it.
4. Start with item 9 only if explicitly requested.
5. Do not modify code unless explicitly told to address a specific issue.
