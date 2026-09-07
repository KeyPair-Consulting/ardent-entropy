# TODO List before completion

## Main coding

1) Add TRACE_END to all seed paths
2) Implement RBG2 vs RBG3 mode
3) Implement all seeds or some seed policy
4) Implement async gather in all async_seed.c
5) Log message about async mode at startup
6) Better state handling from bottom to top
    * Implement ready vs not-ready vs error
    * Ignore sources in error state
    * Handle source degradation (e.g. max gather retry)
7) Validate and harden Windows debug IPC support
    * Build and runtime-test keypair_debug against named pipes
    * Verify OPENSSL_CONF representation of named-pipe paths
    * Add busy-pipe retry and improve Windows error reporting
8) RESERVED to maintain ordinal values
9) Implement Profiling runtime communications
    * Create a thin abstration layer for POSIX/WINDOWS (kpep_shm.c and kpep_event.c)
    * SHM for data plane
    * Signaling for wakeup
    * Shared Object for client-side
      * Accept callback pointers
      * Start profiling with config
      * Monitor events, signal callback with data
    * Example application that uses the Shared Object

## Finalization

1) Verify Error string
2) Verify version numbers
