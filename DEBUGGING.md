# KPEP Debugging Guide

KPEP provides trace and profile facilities for diagnosing entropy-source behavior. Startup settings are read from environment variables so provider initialization and early entropy collection can be captured; a configured local IPC endpoint can later replace those settings without restarting the application that loaded the provider.

## Features

| Feature | Purpose | Startup control | Runtime control |
| --- | --- | --- | --- |
| Trace | Emits timestamped diagnostic messages for selected KPEP subsystems. | `KPEP_TRACE_*` environment variables | `[trace]` section sent through local IPC |
| Profile | Records seed-source timing statistics. | `KPEP_PROFILE_*` environment variables | `[profile]` section sent through local IPC |

Runtime configuration applies both feature sections as one complete request. Invalid runtime configuration is rejected and the active feature configuration is left unchanged.

## Startup Configuration

Set environment variables before the enterprise application loads the KPEP provider. These values are read when provider startup calls the debug subsystem, allowing trace output to include the provider initialization sequence and profiling to begin before initial entropy collection.

| Variable | Meaning |
| --- | --- |
| `KPEP_TRACE_FILE` | Trace output destination: `stdout`, `stderr`, or a filename. |
| `KPEP_TRACE_SEED` | Enable seed-source trace messages only when set to `1`. |
| `KPEP_TRACE_SINK` | Enable logging-sink trace messages using the same flag rules. |
| `KPEP_TRACE_THREAD` | Enable thread trace messages using the same flag rules. |
| `KPEP_TRACE_STRICT` | Flush trace output after each write only when set to `1`. |
| `KPEP_PROFILE_FILE` | Profile output destination: `stdout`, `stderr`, or a filename. |
| `KPEP_PROFILE_INTERVAL` | Profile interval as an unsigned 32-bit integer. `0` is valid. |
| `KPEP_PROFILE_EACH_SAMPLE` | Enable per-sample profiling only when set to `1`. |

For example, the following enables early trace collection to a file:

```sh
export KPEP_TRACE_FILE=/var/tmp/kpep.trace
export KPEP_TRACE_SEED=1
```

## Runtime Reconfiguration

Runtime reconfiguration is optional. It is enabled only when the provider's immutable OpenSSL configuration contains `debug-ipc-path`. The provider creates a local IPC listener after provider initialization completes; a running `keypair_debug` utility sends a complete configuration file to that endpoint and receives a one-byte success or failure acknowledgment.

The endpoint policy is fixed for the lifetime of the loaded provider. Runtime requests replace trace and profile configuration only; they do not change the IPC endpoint or its security mode.

## Provider IPC Configuration

Add these settings to the KPEP provider section in the OpenSSL configuration. The project sample uses `[kpep_sect]` in [resources/kpepmodule.cnf](resources/kpepmodule.cnf).

```ini
[kpep_sect]
debug-ipc-path = /var/run/kpep-debug.sock
debug-security = peer
```

| Setting | Required | Meaning |
| --- | --- | --- |
| `debug-ipc-path` | To enable runtime reconfiguration | Unix-domain socket path on Unix systems; named-pipe path on Windows. |
| `debug-security` | No | `none` or `peer`. When omitted, `none` is used. |

If `debug-ipc-path` is absent or empty, no listener is started. Startup environment-variable debugging remains available, but no runtime configuration request can be applied.

## Security Modes

`none` accepts local connections to the configured endpoint without a peer identity check. Use it only where local access to the endpoint is already sufficiently controlled.

`peer` requires an administrative peer identity before the provider processes the configuration payload. The current implementations accept UID 0 on Linux, macOS, BSD, and Solaris; the Windows implementation checks membership in the local Administrators group.

On Unix, use an endpoint directory that is writable only by the appropriate administrator account or group. The provider creates the socket with a restrictive `umask` in `peer` mode.

## keypair_debug

`keypair_debug` is the local client for generating and applying runtime debug configuration. It honors `OPENSSL_CONF` when looking up the configured IPC path and falls back to OpenSSL's default configuration-file location when `OPENSSL_CONF` is unset.

```text
keypair_debug --write-template
keypair_debug [--ipc-path <path>] <config-file>
```

| Invocation | Effect |
| --- | --- |
| `keypair_debug --write-template` | Writes `kpep_trace_template.cnf` in the current directory. |
| `keypair_debug runtime.cnf` | Reads `debug-ipc-path` from `[kpep_sect]` in the OpenSSL configuration, then applies `runtime.cnf`. |
| `keypair_debug --ipc-path /var/run/kpep-debug.sock runtime.cnf` | Uses the supplied endpoint instead of the OpenSSL configuration value. |

The configuration filename is required when applying settings. The client exits nonzero if the file cannot be read, the endpoint cannot be reached, or the provider rejects the configuration.

## Runtime Configuration File

The runtime file uses OpenSSL configuration syntax and must contain every field below. The complete file must be between 1 and 2048 bytes; comments count toward that limit.

```ini
# Debug template for KPEP debugging (tracing and profiling).   
# This template provides all the configuration fields with 
# default settings.  Copy, rename and modify as needed.
# NOTE: All fields in [trace] and [profile] must be present.

[trace]
file = stderr
seed = 0
sink = 0
thread = 0
strict = 0

[profile]
file = stderr
interval = 0
each-sample = 0
```

| Section | Field | Valid values |
| --- | --- | --- |
| `trace` | `file` | `stdout`, `stderr`, or a filename. |
| `trace` | `seed`, `sink`, `thread`, `strict` | Exactly `0` or `1`. |
| `profile` | `file` | `stdout`, `stderr`, or a filename. |
| `profile` | `interval` | An unsigned 32-bit decimal integer, including `0`. |
| `profile` | `each-sample` | Exactly `0` or `1`. |

To disable trace, set all four trace flags to `0`; its `file` field must still be present. To disable profile output, use a valid `file` target and set `each-sample = 0`; profile reporting behavior is otherwise controlled by the profile subsystem.

## Output Destinations

Both features accept `stdout`, `stderr`, or a regular filename as their output destination. The special stream names are lowercase and must match exactly.

When trace and profile request the same destination string, they share one managed sink and one per-sink OpenSSL mutex. A regular file is opened in append mode and closed when the final feature releases it; standard streams are flushed but never closed. Each newly opened sink receives one UTC banner beginning with `KPEP Debug Output`.

## Operational Procedure

1. Configure `debug-ipc-path` and, when required, `debug-security = peer` in the provider's OpenSSL configuration.
2. Start the enterprise application normally. Set startup environment variables first when early provider startup evidence is required.
3. Generate a complete configuration template:

```sh
keypair_debug --write-template
```

4. Edit `kpep_trace_template.cnf` and keep every required field.
5. Apply it to the running provider:

```sh
keypair_debug kpep_trace_template.cnf
```

6. To override the endpoint from the OpenSSL configuration for a single request:

```sh
keypair_debug --ipc-path /var/run/kpep-debug.sock kpep_trace_template.cnf
```

7. Inspect the configured output destination for trace or profile records. Apply another complete configuration file to change or disable settings.

## Troubleshooting

| Symptom | Likely cause | Action |
| --- | --- | --- |
| `No configuration file specified.` | No positional runtime configuration file was supplied. | Supply one file path. |
| `Specify --ipc-path ...` | The CLI override was omitted and `debug-ipc-path` is absent from the effective OpenSSL configuration. | Add `debug-ipc-path` to `[kpep_sect]`, or supply `--ipc-path`. |
| Connection to the IPC endpoint fails | The provider did not start a listener, the endpoint path differs, or permissions deny access. | Verify the provider config, process state, endpoint path, and security mode. |
| `Runtime debug configuration was rejected.` | The payload is incomplete, invalid, oversized, or not authorized. | Start from `--write-template`; verify every field and the 2048-byte limit. |
| No trace output after applying config | All trace flags are `0`, or the output target cannot be opened. | Enable at least one trace flag and verify the destination path. |
| No early startup trace records | Trace was enabled only after provider startup. | Set `KPEP_TRACE_FILE` and at least one `KPEP_TRACE_*` flag before the application starts. |

## Platform Notes

Unix systems use Unix-domain sockets. Linux uses `SO_PEERCRED` for `peer` mode; macOS and BSD use `getpeereid`; Solaris uses `getpeerucred`.

Windows uses named pipes and an Administrators-group check for `peer` mode. Windows support is functional, not strict: paths use narrow-character APIs, and the named-pipe client has not yet received platform build and runtime validation. See [TODO.md](TODO.md) for the remaining Windows IPC validation and hardening work.

## Future Extensions

Additional debug features can add required runtime configuration sections and fields while retaining the same immutable `debug-ipc-path` lifecycle. Any protocol change must preserve bounded input, explicit validation, and the one-byte result acknowledgment used by the current local IPC control path.
