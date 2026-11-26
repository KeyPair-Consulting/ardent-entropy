/*
 * ardent_stress.c
 *
 * OpenSSL 3.5.5 random-number-generation stress test.
 *
 * Build:
 *   cc -std=c11 -O2 -Wall -Wextra -Wpedantic -pthread \
 *      -o ardent_stress ardent_stress.c $(pkg-config --cflags --libs openssl)
 *
 * Example:
 *   ./ardent_stress 12 --prov=4 --seed=3 --drbg --drbg-digest SHA2-256
 *
 * Methods:
 *   --prov[=N]  RAND_bytes_ex()
 *   --seed[=N]  EVP_RAND "ARDENT-SEED"
 *   --drbg[=N]  EVP_RAND "HMAC-DRBG"
 *   --drbg-digest <name>  Digest to use for HMAC-DRBG (default SHA2-256)
 *
 * A method with no explicit "=N" receives an equal share of the remaining
 * threads. Any remainder is assigned one thread at a time to the first
 * unspecified methods in method order.
 *
 * Press Ctrl-C (SIGINT) to stop the test and print the final summary.
 *
 * NOTE:
 * "ARDENT-SEED" must be supplied by an OpenSSL provider available to the
 * application's library context. This program fetches it by name and
 * instantiates it as an EVP_RAND. If your provider requires a different
 * property query, adjust ARDENT_SEED_PROPERTIES below.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/opensslv.h"
#include "openssl/params.h"
#include "openssl/rand.h"
#include "openssl/core_names.h"

#define REQUEST_BYTES 32U
#define DEFAULT_PROGRESS_SECONDS 5U
#define DRBG_STRENGTH 256U

/*
 * Leave this as NULL to use the default OpenSSL provider/property selection.
 * Set it to a provider property query if ARDENT-SEED requires one.
 */
#define ARDENT_SEED_PROPERTIES NULL
#define DEFAULT_DRBG_DIGEST "SHA2-256"

enum method_id {
    METHOD_PROV = 0,
    METHOD_SEED,
    METHOD_DRBG,
    METHOD_COUNT
};

static const char *const method_names[METHOD_COUNT] = {
    "prov",
    "seed",
    "drbg"
};

struct method_config {
    bool enabled;
    bool explicit_threads;
    unsigned int threads;
};

struct method_stats {
    atomic_uint_fast64_t operations;
    atomic_uint_fast64_t failures;
    atomic_uint_fast64_t bytes;
};

struct app_config {
    unsigned int total_threads;
    struct method_config methods[METHOD_COUNT];
    EVP_RAND *rand[METHOD_COUNT];
    char drbg_digest[32];
};

struct worker_arg {
    enum method_id method;
    unsigned int worker_number;
    struct method_stats *stats;
    EVP_RAND *rand;
    const char *digest;
};

static atomic_bool g_stop = false;
static atomic_bool g_started = false;

static void print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s <total_threads> [--prov[=N]] [--seed[=N]] "
            "[--drbg[=N]]\n"
            "\n"
            "  <total_threads>  Total number of worker threads (> 0)\n"
            "  --prov[=N]       Use RAND_bytes_ex(), optionally N threads\n"
            "  --seed[=N]       Fetch ARDENT-SEED as an EVP_RAND, optionally N threads\n"
            "  --drbg[=N]       Fetch HMAC-DRBG as an EVP_RAND, optionally N threads\n"
            "  --drbg-digest <name>  Set the digest for HMAC-DRBG (default SHA2-256)\n"
            "\n"
            "If N is omitted, that method shares remaining threads equally "
            "with other unspecified methods.\n"
            "Press Ctrl-C to stop and print a summary.\n",
            prog);
}

static bool parse_positive_uint(const char *text, unsigned int *value)
{
    char *end = NULL;
    unsigned long parsed;

    if (text == NULL || *text == '\0' || text[0] == '-') {
        return false;
    }

    errno = 0;
    parsed = strtoul(text, &end, 10);

    if (errno != 0 || end == text || *end != '\0' ||
        parsed == 0 || parsed > UINT_MAX) {
        return false;
    }

    *value = (unsigned int)parsed;
    return true;
}

static int parse_method_arg(const char *arg, enum method_id *method,
                            bool *has_value, unsigned int *value)
{
    static const char *const prefixes[METHOD_COUNT] = {
        "--prov",
        "--seed",
        "--drbg"
    };
    size_t i;

    for (i = 0; i < METHOD_COUNT; ++i) {
        size_t prefix_len = strlen(prefixes[i]);

        if (strcmp(arg, prefixes[i]) == 0) {
            *method = (enum method_id)i;
            *has_value = false;
            *value = 0;
            return 1;
        }

        if (strncmp(arg, prefixes[i], prefix_len) == 0 &&
            arg[prefix_len] == '=') {
            if (!parse_positive_uint(arg + prefix_len + 1, value)) {
                return -1;
            }

            *method = (enum method_id)i;
            *has_value = true;
            return 1;
        }
    }

    return 0;
}

static int parse_args(int argc, char **argv, struct app_config *config)
{
    unsigned int i;
    unsigned int explicit_total = 0;
    unsigned int unspecified_count = 0;
    unsigned int remaining;
    unsigned int base;
    unsigned int remainder;

    memset(config, 0, sizeof(*config));

    if (argc < 3) {
        print_usage(argv[0]);
        return -1;
    }

    if (!parse_positive_uint(argv[1], &config->total_threads)) {
        fprintf(stderr, "Invalid total thread count: %s\n", argv[1]);
        return -1;
    }

    strncpy(config->drbg_digest, DEFAULT_DRBG_DIGEST,
            sizeof(config->drbg_digest) - 1);
    config->drbg_digest[sizeof(config->drbg_digest) - 1] = '\0';

    for (i = 2; i < (unsigned int)argc; ++i) {
        enum method_id method;
        bool has_value;
        unsigned int value;

        if (strcmp(argv[i], "--drbg-digest") == 0) {
            if ((argc <= i+1) || (argv[i+1][0] == '-')) {
                fprintf(stderr, "Argument '--drbg-digest' requires an additional argument with the digest name\n");
                return -1;
            }
            strncpy(config->drbg_digest, argv[++i], sizeof(config->drbg_digest) - 1);
            config->drbg_digest[sizeof(config->drbg_digest) - 1] = '\0';
            continue;
        }

        if (strncmp(argv[i], "--drbg-digest=", 14) == 0) {
            strncpy(config->drbg_digest, argv[i] + 14, sizeof(config->drbg_digest) - 1);
            config->drbg_digest[sizeof(config->drbg_digest) - 1] = '\0';
            continue;
        }

        int result = parse_method_arg(argv[i], &method, &has_value, &value);

        if (result <= 0) {
            fprintf(stderr, "Invalid option: %s\n", argv[i]);
            print_usage(argv[0]);
            return -1;
        }

        if (config->methods[method].enabled) {
            fprintf(stderr, "Duplicate method option: %s\n", argv[i]);
            return -1;
        }

        config->methods[method].enabled = true;
        config->methods[method].explicit_threads = has_value;
        config->methods[method].threads = has_value ? value : 0;

        if (has_value) {
            if (value > config->total_threads - explicit_total) {
                fprintf(stderr,
                        "Explicit thread allocation exceeds total thread count.\n");
                return -1;
            }
            explicit_total += value;
        } else {
            ++unspecified_count;
        }
    }

    if (unspecified_count == 0 && explicit_total != config->total_threads) {
        fprintf(stderr,
                "All enabled methods have explicit counts, so their counts "
                "must sum to total_threads (%u); got %u.\n",
                config->total_threads, explicit_total);
        return -1;
    }

    remaining = config->total_threads - explicit_total;

    if (unspecified_count > 0) {
        base = remaining / unspecified_count;
        remainder = remaining % unspecified_count;

        /*
         * An unspecified method can legitimately receive zero threads if
         * explicit allocations consume the entire total.
         */
        for (i = 0; i < METHOD_COUNT; ++i) {
            if (config->methods[i].enabled &&
                !config->methods[i].explicit_threads) {
                config->methods[i].threads = base;
                if (remainder > 0) {
                    ++config->methods[i].threads;
                    --remainder;
                }
            }
        }
    }

    return 0;
}

static void print_allocation(const struct app_config *config)
{
    unsigned int i;

    printf("OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("Total worker threads: %u\n", config->total_threads);
    printf("Allocation:\n");

    for (i = 0; i < METHOD_COUNT; ++i) {
        if (config->methods[i].enabled) {
            printf("  --%s: %u thread%s%s\n",
                   method_names[i],
                   config->methods[i].threads,
                   config->methods[i].threads == 1 ? "" : "s",
                   config->methods[i].explicit_threads ? " (explicit)" : "");
        }
    }
    fflush(stdout);
}

static void print_openssl_errors(const char *where)
{
    fprintf(stderr, "%s failed:\n", where);
    ERR_print_errors_fp(stderr);
}

static void *worker_prov(void *arg)
{
    struct worker_arg *worker = (struct worker_arg *)arg;
    unsigned char buffer[REQUEST_BYTES];

    (void)worker->worker_number;

    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        int rc = RAND_bytes_ex(NULL, buffer, sizeof(buffer), DRBG_STRENGTH);

        if (rc == 1) {
            atomic_fetch_add_explicit(&worker->stats->operations, 1,
                                      memory_order_relaxed);
            atomic_fetch_add_explicit(&worker->stats->bytes, sizeof(buffer),
                                      memory_order_relaxed);
        } else {
            atomic_fetch_add_explicit(&worker->stats->failures, 1,
                                      memory_order_relaxed);
            /*
             * Avoid a tight failure loop if the provider/entropy subsystem
             * enters an error state.
             */
            sched_yield();
        }
    }

    OPENSSL_cleanse(buffer, sizeof(buffer));
    return NULL;
}

static EVP_RAND *fetch_rand(const char *name, const char *properties)
{
    EVP_RAND *rand;

    rand = EVP_RAND_fetch(NULL, name, properties);
    if (rand == NULL) {
        fprintf(stderr, "EVP_RAND_fetch(\"%s\") failed.\n", name);
        print_openssl_errors("EVP_RAND_fetch");
        return NULL;
    }

    return rand;
}

static EVP_RAND_CTX *create_rand_ctx(EVP_RAND *rand,
                                     const char *name,
                                     const char *digest,
                                     unsigned int worker_number)
{
    EVP_RAND_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    size_t nparams = 0;

    ctx = EVP_RAND_CTX_new(rand, NULL);
    if (ctx == NULL) {
        fprintf(stderr, "[%s worker %u] EVP_RAND_CTX_new() failed.\n",
                name, worker_number);
        print_openssl_errors("EVP_RAND_CTX_new");
        return NULL;
    }

    if (digest != NULL) {
        params[nparams++] =
            OSSL_PARAM_construct_utf8_string("digest",
                                             (char *)digest, 0);
    }

    if (strcmp(name, "HMAC-DRBG") == 0) {
        params[nparams++] =
            OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC,
                                             "HMAC", 0);
    }

    params[nparams] = OSSL_PARAM_construct_end();

    if (!EVP_RAND_instantiate(ctx, DRBG_STRENGTH, 0, NULL, 0, params)) {
        fprintf(stderr, "[%s worker %u] EVP_RAND_instantiate() failed.\n",
                name, worker_number);
        print_openssl_errors("EVP_RAND_instantiate");
        EVP_RAND_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

static int preflight_fetches(struct app_config *config)
{
    unsigned int i;

    /* Providers are deliberately not explicitly loaded. The application
     * uses the normal OpenSSL provider configuration. Fetches happen once,
     * before worker creation, to avoid concurrent first-use fetches. */
    for (i = 0; i < METHOD_COUNT; ++i) {
        if (!config->methods[i].enabled || config->methods[i].threads == 0)
            continue;

        switch ((enum method_id)i) {
        case METHOD_PROV:
            break;
        case METHOD_SEED:
            printf("Preflight: fetching ARDENT-SEED...\n");
            config->rand[i] = fetch_rand("ARDENT-SEED", ARDENT_SEED_PROPERTIES);
            if (config->rand[i] == NULL) return -1;
            printf("Preflight: ARDENT-SEED fetch succeeded.\n");
            break;
        case METHOD_DRBG:
            printf("Preflight: fetching HMAC-DRBG...\n");
            config->rand[i] = fetch_rand("HMAC-DRBG", NULL);
            if (config->rand[i] == NULL) return -1;
            printf("Preflight: HMAC-DRBG fetch succeeded.\n");
            break;
        default:
            return -1;
        }
    }

    fflush(stdout);
    return 0;
}

static void free_fetched_rands(struct app_config *config)
{
    unsigned int i;
    for (i = 0; i < METHOD_COUNT; ++i) {
        EVP_RAND_free(config->rand[i]);
        config->rand[i] = NULL;
    }
}

static void *worker_seed(void *arg)
{
    struct worker_arg *worker = (struct worker_arg *)arg;
    EVP_RAND_CTX *ctx = NULL;
    unsigned char buffer[REQUEST_BYTES];

    (void)worker->worker_number;

    ctx = create_rand_ctx(worker->rand, "ARDENT-SEED", NULL,
                          worker->worker_number);
    if (ctx == NULL) {
        atomic_fetch_add_explicit(&worker->stats->failures, 1,
                                  memory_order_relaxed);
        return NULL;
    }

    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        if (EVP_RAND_generate(ctx, buffer, sizeof(buffer), DRBG_STRENGTH,
                              0, NULL, 0)) {
            atomic_fetch_add_explicit(&worker->stats->operations, 1,
                                      memory_order_relaxed);
            atomic_fetch_add_explicit(&worker->stats->bytes, sizeof(buffer),
                                      memory_order_relaxed);
        } else {
            atomic_fetch_add_explicit(&worker->stats->failures, 1,
                                      memory_order_relaxed);
            sched_yield();
        }
    }

    OPENSSL_cleanse(buffer, sizeof(buffer));
    EVP_RAND_CTX_free(ctx);
    return NULL;
}

static void *worker_drbg(void *arg)
{
    struct worker_arg *worker = (struct worker_arg *)arg;
    EVP_RAND_CTX *ctx = NULL;
    unsigned char buffer[REQUEST_BYTES];

    (void)worker->worker_number;

    ctx = create_rand_ctx(worker->rand, "HMAC-DRBG",
                          worker->digest,
                          worker->worker_number);
    if (ctx == NULL) {
        atomic_fetch_add_explicit(&worker->stats->failures, 1,
                                  memory_order_relaxed);
        return NULL;
    }

    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        if (EVP_RAND_generate(ctx, buffer, sizeof(buffer), DRBG_STRENGTH,
                              0, NULL, 0)) {
            atomic_fetch_add_explicit(&worker->stats->operations, 1,
                                      memory_order_relaxed);
            atomic_fetch_add_explicit(&worker->stats->bytes, sizeof(buffer),
                                      memory_order_relaxed);
        } else {
            atomic_fetch_add_explicit(&worker->stats->failures, 1,
                                      memory_order_relaxed);
            sched_yield();
        }
    }

    OPENSSL_cleanse(buffer, sizeof(buffer));
    EVP_RAND_CTX_free(ctx);
    return NULL;
}

static void *(*worker_function(enum method_id method))(void *)
{
    switch (method) {
    case METHOD_PROV:
        return worker_prov;
    case METHOD_SEED:
        return worker_seed;
    case METHOD_DRBG:
        return worker_drbg;
    default:
        return NULL;
    }
}

static double monotonic_seconds(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0.0;
    }

    return (double)ts.tv_sec + ((double)ts.tv_nsec / 1000000000.0);
}

static void print_progress(const struct app_config *config,
                           struct method_stats *stats,
                           double elapsed)
{
    unsigned int i;

    printf("\nProgress after %.1f seconds:\n", elapsed);

    for (i = 0; i < METHOD_COUNT; ++i) {
        uint64_t ops;
        uint64_t failures;
        uint64_t bytes;
        double rate;

        if (!config->methods[i].enabled) {
            continue;
        }

        ops = atomic_load_explicit(&stats[i].operations,
                                   memory_order_relaxed);
        failures = atomic_load_explicit(&stats[i].failures,
                                        memory_order_relaxed);
        bytes = atomic_load_explicit(&stats[i].bytes,
                                     memory_order_relaxed);
        rate = elapsed > 0.0 ? (double)ops / elapsed : 0.0;

        printf("  --%-4s threads=%-5u ops=%" PRIu64
               " failures=%" PRIu64 " rate=%.3f Mops/s data=%.3f GiB\n",
               method_names[i],
               config->methods[i].threads,
               ops,
               failures,
               rate / 1000000.0,
               (double)bytes / (1024.0 * 1024.0 * 1024.0));
    }

    fflush(stdout);
}

static void print_summary(const struct app_config *config,
                          struct method_stats *stats,
                          double elapsed)
{
    uint64_t total_ops = 0;
    uint64_t total_failures = 0;
    uint64_t total_bytes = 0;
    unsigned int i;

    printf("\n========== Final Summary ==========\n");
    printf("Elapsed time: %.3f seconds\n", elapsed);

    for (i = 0; i < METHOD_COUNT; ++i) {
        uint64_t ops;
        uint64_t failures;
        uint64_t bytes;
        double rate;

        if (!config->methods[i].enabled) {
            continue;
        }

        ops = atomic_load_explicit(&stats[i].operations,
                                   memory_order_relaxed);
        failures = atomic_load_explicit(&stats[i].failures,
                                        memory_order_relaxed);
        bytes = atomic_load_explicit(&stats[i].bytes,
                                     memory_order_relaxed);
        rate = elapsed > 0.0 ? (double)ops / elapsed : 0.0;

        total_ops += ops;
        total_failures += failures;
        total_bytes += bytes;

        printf("--%s: threads=%u, operations=%" PRIu64
               ", failures=%" PRIu64 ", %.3f Mops/s, %.3f GiB\n",
               method_names[i],
               config->methods[i].threads,
               ops,
               failures,
               rate / 1000000.0,
               (double)bytes / (1024.0 * 1024.0 * 1024.0));
    }

    printf("TOTAL: operations=%" PRIu64 ", failures=%" PRIu64
           ", %.3f Mops/s, %.3f GiB\n",
           total_ops,
           total_failures,
           elapsed > 0.0 ? ((double)total_ops / elapsed) / 1000000.0 : 0.0,
           (double)total_bytes / (1024.0 * 1024.0 * 1024.0));
    printf("===================================\n");
}

static void handle_sigint(int signo)
{
    (void)signo;

    /*
     * Only async-signal-safe operations belong in a signal handler.
     * atomic_store on lock-free atomic_bool is used here; the application
     * installs this handler specifically to request worker termination.
     */
    atomic_store_explicit(&g_stop, true, memory_order_relaxed);
}

static int install_signal_handler(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = handle_sigint;
    action.sa_flags = 0;

    if (sigaction(SIGINT, &action, NULL) != 0) {
        perror("sigaction(SIGINT)");
        return -1;
    }

    if (sigaction(SIGTERM, &action, NULL) != 0) {
        perror("sigaction(SIGTERM)");
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct app_config config;
    struct method_stats stats[METHOD_COUNT];
    pthread_t *threads = NULL;
    struct worker_arg *worker_args = NULL;
    unsigned int created = 0;
    unsigned int i;
    double start_time;
    double last_progress;
    int rc = EXIT_FAILURE;

    if (parse_args(argc, argv, &config) != 0) {
        return EXIT_FAILURE;
    }

    for (i = 0; i < METHOD_COUNT; ++i) {
        atomic_init(&stats[i].operations, 0);
        atomic_init(&stats[i].failures, 0);
        atomic_init(&stats[i].bytes, 0);
    }

    threads = calloc(config.total_threads, sizeof(*threads));
    worker_args = calloc(config.total_threads, sizeof(*worker_args));

    if (threads == NULL || worker_args == NULL) {
        fprintf(stderr, "Unable to allocate worker metadata.\n");
        goto cleanup;
    }

    if (install_signal_handler() != 0) {
        goto cleanup;
    }

    print_allocation(&config);

    if (preflight_fetches(&config) != 0) {
        fprintf(stderr, "Preflight fetch failed; no stress threads started.\n");
        goto cleanup;
    }

    /*
     * Create each worker with its own EVP_RAND_CTX for --seed and --drbg.
     * The --prov workers use RAND_bytes_ex(), whose public RAND state is
     * managed by OpenSSL's thread-safe library internals.
     */
    for (i = 0; i < METHOD_COUNT; ++i) {
        unsigned int worker_number;

        if (!config.methods[i].enabled) {
            continue;
        }

        for (worker_number = 0;
             worker_number < config.methods[i].threads;
             ++worker_number) {
            struct worker_arg *arg = &worker_args[created];
            int create_rc;

            arg->method = (enum method_id)i;
            arg->worker_number = worker_number;
            arg->stats = &stats[i];
            arg->rand = config.rand[i];
            arg->digest = config.drbg_digest;

            create_rc = pthread_create(&threads[created], NULL,
                                       worker_function((enum method_id)i),
                                       arg);
            if (create_rc != 0) {
                fprintf(stderr,
                        "pthread_create failed for --%s worker %u: %s\n",
                        method_names[i], worker_number, strerror(create_rc));
                atomic_store_explicit(&g_stop, true, memory_order_relaxed);
                goto join_threads;
            }

            ++created;
        }
    }

    if (created == 0) {
        fprintf(stderr, "No worker threads were allocated.\n");
        goto cleanup;
    }

    atomic_store_explicit(&g_started, true, memory_order_release);

    start_time = monotonic_seconds();
    last_progress = start_time;

    printf("\nStress test running. Press Ctrl-C to stop.\n");
    fflush(stdout);

    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        struct timespec sleep_time = {
            .tv_sec = 1,
            .tv_nsec = 0
        };
        double now;

        nanosleep(&sleep_time, NULL);
        now = monotonic_seconds();

        if (now - last_progress >= DEFAULT_PROGRESS_SECONDS) {
            print_progress(&config, stats, now - start_time);
            last_progress = now;
        }
    }

    print_progress(&config, stats, monotonic_seconds() - start_time);

join_threads:
    for (i = 0; i < created; ++i) {
        int join_rc = pthread_join(threads[i], NULL);
        if (join_rc != 0) {
            fprintf(stderr, "pthread_join failed: %s\n", strerror(join_rc));
        }
    }

    if (created > 0) {
        double end_time = monotonic_seconds();
        double elapsed = end_time - start_time;

        print_summary(&config, stats, elapsed);
        rc = EXIT_SUCCESS;
    }

cleanup:
    free_fetched_rands(&config);
    free(worker_args);
    free(threads);

    return rc;
}
