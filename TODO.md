# TODO List before completion

## Main coding

1) Add TRACE_END to all seed paths
2) Enforce ctx_prov dependency in load_params (no outside-openssl usage)
3) Implement RBG2 vs RBG3 mode
4) Implement all seeds or some seed policy
5) Implement async gather in all async_seed.c
6) Log message about async mode at startup
7) Better state handling from bottom to top
    * Implement ready vs not-ready vs error
    * Ignore sources in error state
    * Handle source degradation (e.g. max gather retry)
8) Improve profiling
    * implement logging profile data
    * Granularity: log individual samples?
    * Create API for external access
    * Watchdog/worker to implement interval?
9) Add KPEP_PROFILE_EACH_SAMPLE env-var

## Finalization

1) Verify Error string
2) Verify version numbers
