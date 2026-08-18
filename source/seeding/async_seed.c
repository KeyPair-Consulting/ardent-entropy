/* ************************************************************************************************
 * Copyright (C) 2022-2026 Symbiotic Systems Research, LLC
 * All Rights Reserved * Proprietary and confidential
 * 
 * The methods and techniques described herein are considered 
 * trade secrets and/or confidential. Reproduction or distribution, 
 * in whole or in part, is forbidden except by express written 
 * permission of Symbiotic Systems Research, LLC.
 * Please contact <info@symsysresearch.com> for licensing information.
 * 
 * NO WARRANTY, EXPLICIT OR IMPLICIT, IS PROVIDED.
 * In no event shall the author be liable for any claim or damages.
 * 
 * Author: Randall Steck
 * ***********************************************************************************************/

#include "kpep/kpep.h"
#include "kpep/kpep_names.h"
#include "kpep/kpep_cpuinfo.h"
#include "kpep/kpep_seed_stub.h"
#include "rdcpu_toolbox.h"
#include "seed_sources.h"
#include "ringbuffer.h"
#include "async_seed.h"

#include "openssl/params.h"
#include "internal/thread_arch.h"

#include <string.h>

/* ************************************************************************************************
 * ***********************************************************************************************
 * Definitions, declarations, and context structure
 * ***********************************************************************************************
 * ***********************************************************************************************/

#define MODULE_NAME "SEED-ASYNC"

typedef struct async_ctx_st {
    char name[64];

    void                 *source_ctx;
    const SEED_STUB_INFO *source_info;
    const STUB_FUNCTIONS *source_fn;

    RING_CTX             *ring_ctx;

    ASYNC_WORKER_STATE    state;
    CRYPTO_THREAD        *thread;
    CRYPTO_MUTEX         *mutex;
    CRYPTO_CONDVAR       *cond;

} ASYNC_CTX;

static const char *base_name = "ASYNC";

static inline int stub_is_valid(const STUB_FUNCTIONS *stub) {
    return (stub &&
            stub->new_fn &&
            stub->free_fn &&
            stub->gather_fn &&
            stub->get_name_fn &&
            stub->get_state_fn);
}

/* ************************************************************************************************
 * ***********************************************************************************************
 * API functions
 * ***********************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
void async_seed_free(ASYNC_CTX *ctx)
{
    CRYPTO_THREAD_RETVAL retval;

    #if defined (KPEP_TRACE_SEED)
    TRACE_START;
    #endif

    if (!ctx)
        return;

    // Lock for safe shutdown
    if (ctx->mutex)
        ossl_crypto_mutex_lock(ctx->mutex);

    // Handle thread shutdown
    if (ctx->thread) {
        // Signal to stop the thread
        ctx->state = WORKER_STOPPING;
        ossl_crypto_condvar_signal(ctx->cond);
        ossl_crypto_mutex_unlock(ctx->mutex);
        // Wait for thread to finish
        ossl_crypto_thread_native_join(ctx->thread, &retval);
        // Reclaim the mutex for the remainder of shutdown
        ossl_crypto_mutex_lock(ctx->mutex);
        // Check result
        if (ctx->state != WORKER_STOPPED) {
            // Nothing we can do, but log it anyway
            LOG_SIMPLE_ERROR(MODULE_NAME, "Thread did not stop correctly");
        }
        // Thread cleanup
        ossl_crypto_thread_native_clean(ctx->thread);
        ctx->thread = NULL;
    }

    // Free the ring
    if (ctx->ring_ctx)
        ring_free(ctx->ring_ctx);
    // Free the source context
    if (ctx->source_ctx && ctx->source_fn && ctx->source_fn->free_fn)  
        ctx->source_fn->free_fn(ctx->source_ctx);
    // Free the conditional variable
    if (ctx->cond)
        ossl_crypto_condvar_free(&ctx->cond);     
    // Free the mutex
    if (ctx->mutex) {
        ossl_crypto_mutex_unlock(ctx->mutex);
        ossl_crypto_mutex_free(&ctx->mutex);
    }
    // Free the ASYNC_CTX structure itself
    kpep_free(ctx);

    kpep_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'async' shutdown successful");
}

EXPORT_VISIBILITY_HIDDEN
ASYNC_CTX *async_seed_new(void* prov_ctx, const STUB_FUNCTIONS* stub_fn, uint32_t ring_sz, uint8_t idx, KPEP_RESULT *errnum)
{
    ASYNC_CTX *ctx;
    KPEP_RESULT rv;
    int len;

    #if defined (KPEP_TRACE_SEED)
    TRACE_START;
    #endif

#ifdef FIPS_OPTEST
    {
        const char* debug = getenv(ENV_OPTEST_SEED_ASYNC_NEW);
        if (debug) {
            LOG_SIMPLE_ERROR(MODULE_NAME, "Ringbuffer failed startup (optest)");
            if (errnum) *errnum = KPEP_R_FIPS_OPTEST;
            return NULL;
        }
    }
#endif

    if (!stub_fn || !ring_sz) {
        if (errnum) *errnum = KPEP_R_INVALID_ARG;
        return NULL;
    }
    if (!stub_is_valid(stub_fn)) {
        if (errnum) *errnum = KPEP_R_INVALID_ARG;
        return NULL;
    }
        
    // Allocate for source context
    ctx = kpep_zalloc(sizeof(ASYNC_CTX));
    if (ctx == NULL) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Ringbuffer failed startup (malloc)");
        if (errnum) *errnum = KPEP_R_MALLOC_FAIL;
        return NULL;
    }

    // Initialize locks
    ctx->mutex = ossl_crypto_mutex_new();
    if (!ctx->mutex) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Ringbuffer failed startup (create mutex)");
        goto err;
    }
    ctx->cond = ossl_crypto_condvar_new();
    if (!ctx->cond) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Ringbuffer failed startup (create condition variable)");
        goto err;
    }

    // Create the new seed source
    ctx->source_fn = stub_fn;
    ctx->source_ctx = ctx->source_fn->new_fn(prov_ctx, idx, errnum);
    if (!ctx->source_ctx) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Ringbuffer failed startup (new/load params)");
        if (errnum) *errnum = KPEP_R_MALLOC_FAIL;
        goto err;
    }
    ctx->source_info = (SEED_STUB_INFO*) ctx->source_ctx;

    // Safely create seed source name
    len = snprintf(ctx->name,
               sizeof(ctx->name),
               "async (%s)",
               ctx->source_info->name);
    if (len < 0) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Unable to format source name");
        goto err;
    }
    if ((size_t)len >= sizeof(ctx->name)) {
        LOG_FORMATTED_ERROR(MODULE_NAME,
                            "Seed source name '%s' truncated",
                            ctx->source_info->name);
    }

    // Create ring
    rv = ring_new(&ctx->ring_ctx, ring_sz);
    if (rv) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Ringbuffer failed startup (new ring)");
        if (errnum) *errnum = KPEP_R_MALLOC_FAIL;
        goto err;
    }

    // Create the locks
    ctx->mutex = ossl_crypto_mutex_new();
    if (!ctx->mutex) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Ringbuffer failed startup (create mutex)");
        if (errnum) *errnum = KPEP_R_MUTEX_FAIL_START;
        goto err;
    }
    ctx->cond = ossl_crypto_condvar_new();
    if (!ctx->cond) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Ringbuffer failed startup (create condition variable)");
        if (errnum) *errnum = KPEP_R_MUTEX_FAIL_START;
        goto err;
    }

    // Start initialized
    if (ctx->source_info->full_entropy)
        kpep_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'async (%s)' startup successful (full entropy)", ctx->name);
    else 
        kpep_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'async (%s)' startup successful (%.6f ent-per-bit)", ctx->name, ctx->source_info->entropy_per_bit);

    return ctx;

err:
    async_seed_free(ctx);
    return NULL;
}

EXPORT_VISIBILITY_HIDDEN
KPEP_RESULT async_seed_gather(ASYNC_CTX *ctx, unsigned char *out, size_t *out_len, size_t nbits)
{
    KPEP_RESULT rv = KPEP_R_SUCCESS;
    uint32_t gather_bits, gather_bytes;

    #if defined (KPEP_TRACE_SEED)
    TRACE_START;
    #endif

#ifdef FIPS_OPTEST
    {
        const char* debug;
        debug = getenv(ENV_OPTEST_SEED_RDSEED_GATHER);
        if (debug) {
            LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'async' gather failed (optest)");
            return KPEP_R_FIPS_OPTEST;
        }
        debug = getenv(ENV_OPTEST_SEED_RDSEED_FATAL);
        if (debug) {
            LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'async' gather failed (optest-fatal)");
            return KPEP_R_SEED_FATAL_ERROR;
        }
    }
#endif

    if (!nbits)
        return KPEP_R_SUCCESS;

    // Validate context
    if (!ctx || !out_len) {
        LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_NULL_ARG);
        return KPEP_R_NULL_ARG;
    }

    // Calculate gather size
    gather_bits = seed_get_gather_sz(ctx->source_info, nbits);
    gather_bytes = (gather_bits + 7) >> 3;

    #if defined (KPEP_TRACE_SEED)
    kpep_trace_fmt(MODULE_NAME, "%s %lu -> %lu", out?"byte":"size", nbits, gather_bytes<<3);
    #endif

    // Return gather size?
    if (!out) {
        *out_len = gather_bytes;
        return KPEP_R_SUCCESS;
    }

    // Check for adequate size
    if (*out_len < gather_bytes) {
        LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_SEED_BUFFER_TOO_SMALL);
        return KPEP_R_SEED_BUFFER_TOO_SMALL;
    }

    // Check state
    if (ctx->source_info->state != KPEP_RAND_STATE_READY) {
        LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_SEED_NOT_READY);
        return KPEP_R_SEED_NOT_READY;
    }

    // Get the entropy from the source
    ossl_crypto_mutex_lock(ctx->mutex);

    { // This will go in the async thread
        size_t buflen = gather_bytes;
        uint8_t *buf = NULL;
        buf = kpep_zalloc(gather_bytes);
        if (!buf) {
            LOG_FORMATTED_ERROR(MODULE_NAME, "Seed source 'async (%s)' gather malloc failed", ctx->source_info->name);
            ossl_crypto_mutex_unlock(ctx->mutex);  // Need better handling
            goto err;
        }
        rv = ctx->source_fn->gather_fn(ctx->source_ctx, buf, &buflen, nbits);
        if (rv) {
            LOG_FORMATTED_ERROR(MODULE_NAME, "Seed source 'async (%s)' gather operation failed", ctx->source_info->name);
            ossl_crypto_mutex_unlock(ctx->mutex);  // Need better handling
            kpep_free(buf);
            goto err;
        }
        rv = ring_enqueue(ctx->ring_ctx, buf, buflen);
        if (rv) {
            LOG_FORMATTED_ERROR(MODULE_NAME, "Seed source 'async (%s)' write-to-ring failed", ctx->source_info->name);
            ossl_crypto_mutex_unlock(ctx->mutex);  // Need better handling
            kpep_free(buf);
            goto err;
        }
        kpep_free(buf);
    }

    rv = ring_dequeue(ctx->ring_ctx, out, gather_bytes);
    ossl_crypto_mutex_unlock(ctx->mutex);
    if (rv) {
        LOG_FORMATTED_ERROR(MODULE_NAME, "Seed source 'async (%s)' gather failed", ctx->source_info->name);
        goto err;
    }

    // Trigger thread to gather more entropy if needed
    ossl_crypto_mutex_lock(ctx->mutex);
    ossl_crypto_condvar_signal(ctx->cond);
    ossl_crypto_mutex_unlock(ctx->mutex);

    // Success
    *out_len = gather_bytes;
    return KPEP_R_SUCCESS;

err:
    // If no error already set, assume a general error
    if (!rv) {
        LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_ERROR_RETRIEVING_ENTROPY);
        rv = KPEP_R_ERROR_RETRIEVING_ENTROPY;
    }

    // Zeroize
    memset(out, 0, *out_len);
    *out_len = 0;

    // The source state should be "KPEP_RAND_STATE_ERROR"
    return rv;
}

EXPORT_VISIBILITY_HIDDEN
uint32_t async_seed_get_state(ASYNC_CTX *ctx)
{
    if (!ctx)
        return KPEP_RAND_STATE_UNINITIALISED; // Value 0
    return ctx->source_fn->get_state_fn(ctx->source_ctx);
}

EXPORT_VISIBILITY_HIDDEN
const char* async_seed_get_name(ASYNC_CTX *ctx) 
{
    if (!ctx) {
        kpep_log(LOG_LVL_WARN, MODULE_NAME, "get_name(async) called with NULL context (should not happen)");
        return NULL;
    }   
    return ctx->name;
}

/* ************************************************************************************************
 * ***********************************************************************************************
 * API functions
 * ***********************************************************************************************
 * ***********************************************************************************************/

static CRYPTO_THREAD_RETVAL async_worker(void *arg)
{
    ASYNC_CTX *ctx = (ASYNC_CTX *)arg;
    ASYNC_WORKER_STATE local_state;

    printf("Thread (%p) started for %s\n", 
            (void*)(ctx?ctx->thread:NULL),
            ctx?ctx->name:"unknown");

    if (!ctx) {
        printf("Thread started with NULL context\n");
        return 0;
    }

    ossl_crypto_mutex_lock(ctx->mutex);

    if (ctx->state != WORKER_INITIALIZED) {
        printf("Thread started with invalid state\n");
        return 0;
    }

    ctx->state = WORKER_RUNNING;    

    for (;;) {
        ossl_crypto_condvar_wait(ctx->cond, ctx->mutex); /* atomically releases mutex */
        local_state = ctx->state;
        ossl_crypto_mutex_unlock(ctx->mutex);

        if (local_state == WORKER_RUNNING) {
            printf("Thread (%p) gathering...\n", (void*)ctx->thread);
            ossl_crypto_mutex_lock(ctx->mutex);
            continue;
        }
        break; /* STOPPING exits the loop */
    }
    
    ossl_crypto_mutex_lock(ctx->mutex);
    ctx->state = WORKER_STOPPED;
    ossl_crypto_mutex_unlock(ctx->mutex);

    printf("Thread (%p) stopped\n", (void*)ctx->thread);
    return 0;
}

EXPORT_VISIBILITY_HIDDEN
KPEP_RESULT async_seed_start_thread(ASYNC_CTX *ctx)
{
    KPEP_RESULT rv = KPEP_R_SUCCESS;

    if (!ctx) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Thread start called with NULL context");
        return KPEP_R_NULL_ARG;
    }

    if (!ctx->mutex || !ctx->cond) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Thread start called with NULL mutex");
        return KPEP_R_NULL_ARG;
    }
    
    // Lock for startup
    ossl_crypto_mutex_lock(ctx->mutex);

    if (ctx->state != WORKER_UNINITIALIZED) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Thread start called with invalid state");
        rv = KPEP_R_THREAD_NOT_READY;
        goto err;
    }

    // Start the thread.  IMPORTANT: The thread needs the lock to operate, so DO NOT wait
    // on the thread's behavior or some change in the thread state to release the lock.  
    // Release it ASAP after starting the thread!
    ctx->state = WORKER_INITIALIZED;  // "Initialized" state tells the thread to go
    ctx->thread = ossl_crypto_thread_native_start(async_worker, ctx, 1);
    if (!ctx->thread) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Failed to start thread");
        rv = KPEP_R_THREAD_NOT_READY;
        goto err;
    }

err:
    ossl_crypto_mutex_unlock(ctx->mutex);
    return rv;
}
