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
#include "seed_ringbuffer.h"

#include "openssl/params.h"
#include "internal/thread_once.h"

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

    CRYPTO_RWLOCK        *lock;
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
void async_ringbuffer_free(ASYNC_CTX *ctx)
{
    #if defined (KPEP_TRACE_SEED)
    TRACE_START;
    #endif

    if (!ctx)
        return;

    if (ctx->ring_ctx)
        ring_free(ctx->ring_ctx);                 // Free the ring
    if (ctx->source_ctx && ctx->source_fn && ctx->source_fn->free_fn)  
        ctx->source_fn->free_fn(ctx->source_ctx); // Free the source
    if (ctx->lock)
        CRYPTO_THREAD_lock_free(ctx->lock);       // Free the lock
    kpep_free(ctx);

    kpep_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'async' shutdown successful");
}

EXPORT_VISIBILITY_HIDDEN
void* async_ringbuffer_new(void* prov_ctx, const STUB_FUNCTIONS* stub_fn, uint32_t ring_sz, uint8_t idx, KPEP_RESULT *errnum)
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
    ctx->lock = CRYPTO_THREAD_lock_new();
    if (!ctx->lock) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Ringbuffer failed startup (create lock)");
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

    // Start initialized
    if (ctx->source_info->full_entropy)
        kpep_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'async (%s)' startup successful (full entropy)", ctx->name);
    else
        kpep_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'async (%s)' startup successful (%.6f ent-per-bit)", ctx->name, ctx->source_info->entropy_per_bit);

    return ctx;

err:
    async_ringbuffer_free(ctx);
    return NULL;
}

EXPORT_VISIBILITY_HIDDEN
KPEP_RESULT async_ringbuffer_gather(ASYNC_CTX *ctx, unsigned char *out, size_t *out_len, size_t nbits)
{
    KPEP_RESULT rv = KPEP_R_SUCCESS;
    size_t gather_sz, gather_ovf;

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

    // Calculate gather size and Quantize to block size
    gather_sz = (ctx->source_info->full_entropy)?nbits:(size_t) (nbits / ctx->source_info->entropy_per_bit);
    gather_ovf = (gather_sz % ctx->source_info->block_size);
    if (gather_ovf)
        gather_sz += (ctx->source_info->block_size - gather_ovf);
    gather_sz = gather_sz>>3;  // Bits to bytes

    #if defined (KPEP_TRACE_SEED)
    kpep_trace_fmt(MODULE_NAME, "%s %lu -> %lu", out?"byte":"size", nbits, gather_sz<<3);
    #endif

    // Return gather size?
    if (!out) {
        *out_len = gather_sz;
        return KPEP_R_SUCCESS;
    }

    // Check for adequate size
    if (*out_len < gather_sz) {
        LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_SEED_BUFFER_TOO_SMALL);
        return KPEP_R_SEED_BUFFER_TOO_SMALL;
    }

    // Check state
    if (ctx->source_info->state != KPEP_RAND_STATE_READY) {
        LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_SEED_NOT_READY);
        return KPEP_R_SEED_NOT_READY;
    }

    // Get the entropy from the source
    if (ctx->lock && !CRYPTO_THREAD_write_lock(ctx->lock)) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Failed to obtain lock (async_generate)");
        goto err;
    }

    { // This will go in the async thread
        size_t buflen = gather_sz;
        uint8_t *buf = NULL;
        buf = kpep_zalloc(gather_sz);
        if (!buf) {
            LOG_FORMATTED_ERROR(MODULE_NAME, "Seed source 'async (%s)' gather malloc failed", ctx->source_info->name);
            goto err;
        }
        rv = ctx->source_fn->gather_fn(ctx->source_ctx, buf, &buflen, nbits);
        if (rv) {
            LOG_FORMATTED_ERROR(MODULE_NAME, "Seed source 'async (%s)' gather operation failed", ctx->source_info->name);
            kpep_free(buf);
            goto err;
        }
        rv = ring_enqueue(ctx->ring_ctx, buf, buflen);
        if (rv) {
            LOG_FORMATTED_ERROR(MODULE_NAME, "Seed source 'async (%s)' write-to-ring failed", ctx->source_info->name);
            kpep_free(buf);
            goto err;
        }
        kpep_free(buf);
    }

    rv = ring_dequeue(ctx->ring_ctx, out, gather_sz);
    if (ctx->lock && !CRYPTO_THREAD_unlock(ctx->lock)) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Failed to release lock (async_generate)");
    }
    if (rv) {
        LOG_FORMATTED_ERROR(MODULE_NAME, "Seed source 'async (%s)' gather failed", ctx->source_info->name);
        goto err;
    }

    // Success
    *out_len = gather_sz;
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
uint32_t  async_ringbuffer_get_state(ASYNC_CTX *ctx)
{
    if (!ctx)
        return KPEP_RAND_STATE_UNINITIALISED; // Value 0
    return ctx->source_fn->get_state_fn(ctx->source_ctx);
}

EXPORT_VISIBILITY_HIDDEN
const char* async_ringbuffer_get_name(ASYNC_CTX *ctx) 
{
    if (!ctx) {
        kpep_log(LOG_LVL_WARN, MODULE_NAME, "get_name(async) called with NULL context (should not happen)");
        return NULL;
    }   
    return ctx->name;
}

