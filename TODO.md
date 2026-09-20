# TODO List before completion

## Main coding

1) Add TRACE_END to all seed paths
2) Implement RBG2 vs RBG3 mode                *** IMPL; NEEDS TESTING
3) Implement all seeds or some seed policy    *** IMPL; NEEDS TESTING
4) Log message about async mode at startup    *** IMPL; NEEDS TESTING
5) Implement async gather in all async_seed.c
6) Better state handling from bottom to top
    * Implement ready vs not-ready vs error
    * Ignore sources in error state
    * Handle source degradation (e.g. max gather retry)
7) Validate and harden Windows debug IPC support
    * Build and runtime-test keypair_debug against named pipes
    * Verify OPENSSL_CONF representation of named-pipe paths
    * Add busy-pipe retry and improve Windows error reporting
8) Update CPUINFO
    * Use OpenSSL internal API via file import
    * Use Google's cpu_info project
9) Implement Profiling runtime communications
    * Create a thin abstration layer for POSIX/WINDOWS (kpep_shm.c and kpep_event.c)
    * SHM for data plane
    * Signaling for wakeup
    * Shared Object for client-side
      * Accept callback pointers
      * Start profiling with config
      * Monitor events, signal callback with data
    * Example application that uses the Shared Object
10) Test all 3 methods of entropy for routing to KPEP

## Finalization

1) Verify Error string
2) Verify version numbers
