/* ************************************************************************************************
 * Copyright (C) 2026 Symbiotic Systems Research, LLC
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
#include "kpep/kpep_seed_stub.h"
#include "seed_sources.h"

#include "openssl/params.h"
#include "jitterentropy.h"

//KPEP: For Debugging "__func__"
#include <stdio.h>

/* ***********************************************************************************************
 * ***********************************************************************************************
 * Definitions, declarations, and context structure
 * ***********************************************************************************************
 * ***********************************************************************************************/

// Required flags, per ESV E239
#define JENT_KPEP_FLAGS JENT_FORCE_FIPS | JENT_DISABLE_INTERNAL_TIMER

#define JITTER_MAX_NUM_TRIES 3

#define MODULE_NAME "SEED-JITTER"

typedef struct {
    COMMON_STUB_INFO  // See seed_context.h

    // Source-specific parameters
    unsigned int osr; 
} JITTER_CTX;

static KPEP_RESULT load_params(void* prov_ctx, JITTER_CTX *ctx);

#define str(a) #a
#define stringify(a) str(a)
static const char *base_name = "Jitter Entropy (v" \
                                stringify(JENT_MAJVERSION) "." \
                                stringify(JENT_MINVERSION) "." \
                                stringify(JENT_PATCHLEVEL) ")";

/* ***********************************************************************************************
 * ***********************************************************************************************
 * Stub functions
 * ***********************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
void stub_jitter_free(void *ctx)
{
    if (kpep_trace_seed_enabled) {
        TRACE_START;
    }

    kpep_cleanse(ctx, sizeof(JITTER_CTX));
    kpep_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'jitter' shutdown successful");
}
 
EXPORT_VISIBILITY_HIDDEN
void* stub_jitter_new(void* prov_ctx, uint32_t idx, KPEP_RESULT *errnum)
{
    JITTER_CTX *ctx;
    KPEP_RESULT result;
    size_t full_entropy_sz;
    int ret;
    uint32_t len;

    if (kpep_trace_seed_enabled) {
        TRACE_START;
    }

#ifdef FIPS_OPTEST
    {
        const char* debug = getenv(ENV_OPTEST_SEED_JITTER_NEW);
        if (debug) {
            LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'jitter' failed startup (optest)");
            if (errnum) *errnum = KPEP_R_FIPS_OPTEST;
            return NULL;
        }
    }
#endif

    // Allocate for source context
    ctx = kpep_zalloc(sizeof(JITTER_CTX));
    if (ctx == NULL) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'jitter' failed startup (malloc)");
        if (errnum) *errnum = KPEP_R_MALLOC_FAIL;
        return NULL;
    }

    // Pull runtime configuration from params
    if ((result = load_params(prov_ctx, ctx)) != KPEP_R_SUCCESS) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'jitter' failed startup (load params)");
        kpep_cleanse(ctx, sizeof(JITTER_CTX));
        if (errnum) *errnum = result;
        return NULL;        
    }

    // Set entropy factors
    full_entropy_sz = ctx->block_size * ctx->block_count;
    if (full_entropy_sz < KPEP_SECURITY_STRENGTH_BITS) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'jitter' failed startup (block size check)");
        kpep_cleanse(ctx, sizeof(JITTER_CTX));
        if (errnum) *errnum = KPEP_R_INVALID_ARG;
        return NULL;        
    }
    ctx->full_entropy = (KPEP_SECURITY_STRENGTH_BITS == full_entropy_sz);
    if (!ctx->full_entropy)
        ctx->entropy_per_bit = (double) KPEP_SECURITY_STRENGTH_BITS / (double) full_entropy_sz;

    // Name
    len = snprintf(ctx->name,
                sizeof(ctx->name),
                "%s",
                base_name);
    if (len < 0) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Unable to format source name");
        return NULL;
    }
    if ((size_t)len >= sizeof(ctx->name)) {
        LOG_FORMATTED_ERROR(MODULE_NAME,
                            "Seed source name '%s' truncated",
                            base_name);
    }

    // Initialize source
    if ((ret = jent_entropy_init_ex(ctx->osr, JENT_KPEP_FLAGS)) != 0) {
        LOG_FORMATTED_ERROR(MODULE_NAME, "Seed source 'jitter' failed startup (library); errnum (%d)", ret);
        kpep_cleanse(ctx, sizeof(JITTER_CTX));
        if (errnum) *errnum = KPEP_R_SEED_NOT_INSTANTIATED;
        return NULL;
    }

    // Start initialized
    if (ctx->full_entropy)
        kpep_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'jitter' startup successful (full entropy)");
    else
        kpep_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'jitter' startup successful (%.6f ent-per-bit)", ctx->entropy_per_bit);

    ctx->state = KPEP_RAND_STATE_READY;
    return ctx;
}

EXPORT_VISIBILITY_HIDDEN
JITTER_CTX* pubapi_jitter_new(size_t osr)
{
    KPEP_RESULT rv = KPEP_R_SUCCESS;
    JITTER_CTX* ctx = NULL;

    if (kpep_trace_seed_enabled) {
        TRACE_START;
    }

    ctx = stub_jitter_new(NULL, 0, &rv);
    if (ctx)
        ctx->osr = osr;
    return ctx;
}

EXPORT_VISIBILITY_HIDDEN
KPEP_RESULT stub_jitter_gather(void *stub_ctx, unsigned char *out, size_t *out_len, size_t nbits)
{
    JITTER_CTX *ctx = (JITTER_CTX *)stub_ctx;
    KPEP_RESULT rv = KPEP_R_SUCCESS;
    size_t gather_bits, gather_bytes;

    struct rand_data *jitter_ec = NULL;
    ssize_t result = 0;
    size_t num_tries;
    uint32_t start_us;

    if (kpep_trace_seed_enabled) {
        TRACE_START;
    }

#ifdef FIPS_OPTEST
    {
        const char* debug;
        debug = getenv(ENV_OPTEST_SEED_JITTER_GATHER);
        if (debug) {
            return KPEP_R_FIPS_OPTEST;
        }
        debug = getenv(ENV_OPTEST_SEED_JITTER_FATAL);
        if (debug) {
            return KPEP_R_SEED_FATAL_ERROR;
        }
    }
#endif

    if (!nbits)
        return KPEP_R_SUCCESS;

    // Validate context
    if (!ctx || !out || !out_len) {
        LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_NULL_ARG);
        return KPEP_R_NULL_ARG;
    }

    // Calculate gather size
    gather_bits = seed_get_gather_sz((SEED_STUB_INFO*)ctx, nbits);
    gather_bytes = (gather_bits + 7) >> 3;
    
    if (kpep_trace_seed_enabled) {
        kpep_trace_fmt(MODULE_NAME, "%s %lu -> %lu", out?"byte":"size", nbits, gather_bits);
    }

    // Check for adequate size
    if (*out_len < gather_bytes) {
        LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_SEED_BUFFER_TOO_SMALL);
        return KPEP_R_SEED_BUFFER_TOO_SMALL;
    }

    // Check state
    if (ctx->state != KPEP_RAND_STATE_READY) {
        LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_SEED_NOT_READY);
        return KPEP_R_SEED_NOT_READY;
    }

    // Retry intermittent failures, then give up
    if (kpep_profile_enabled) {
        start_us = seed_stub_profile_now_us();
    }
    for (num_tries = 0; num_tries < JITTER_MAX_NUM_TRIES; num_tries++) {
        /* Allocate a fresh collector */
        jitter_ec = jent_entropy_collector_alloc(ctx->osr, JENT_KPEP_FLAGS);
        if (jitter_ec == NULL)
            continue;

        /* Do not use _safe API as per typical security policies */
        result = jent_read_entropy(jitter_ec, (char *) out, gather_bytes);
        jent_entropy_collector_free(jitter_ec);

        /* Permanent Failure
         * https://github.com/smuellerDD/jitterentropy-library/blob/master/doc/jitterentropy.3#L234
         */
        if (result < -5) {
            LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_SEED_FATAL_ERROR);
            rv = KPEP_R_SEED_FATAL_ERROR;
            break;
        }

        // Success
        if (result >= 0 && (size_t)result == gather_bytes)  {
            if (kpep_profile_enabled) {
                seed_stub_profile_update((SEED_STUB_INFO *)ctx, seed_stub_profile_now_us() - start_us);
            }
            *out_len = gather_bytes;
            return KPEP_R_SUCCESS;
        }
    }
    
    // We are going to be entering a permanent error state, but it's probaby a good idea to still 
    // grab the profiling information.
    if (kpep_profile_enabled) {
        seed_stub_profile_update((SEED_STUB_INFO *)ctx, seed_stub_profile_now_us() - start_us);
    }

    // If no error already set, assume a general error
    if (!rv)
        rv = KPEP_R_ERROR_RETRIEVING_ENTROPY;

    // Zeroize
    memset(out, 0, *out_len);
    *out_len = 0;

    // Permanent failure or too many intermittent failures
    ctx->state = KPEP_RAND_STATE_ERROR;
    return rv;
}

EXPORT_VISIBILITY_HIDDEN
uint32_t stub_jitter_get_state(void* stub_ctx)
{
    JITTER_CTX *ctx = (JITTER_CTX *)stub_ctx;
    if (!ctx) 
        return KPEP_RAND_STATE_UNINITIALISED; // Value 0
    return ctx->state;
}

EXPORT_VISIBILITY_HIDDEN
const char* stub_jitter_get_name(void* stub_ctx) 
{
    JITTER_CTX *ctx = (JITTER_CTX *)stub_ctx;
    if (!ctx) {
        kpep_log(LOG_LVL_WARN, MODULE_NAME, "get_name(jitter) called with NULL context (should not happen)");
        return NULL;
    }   
    return (const char*) ctx->name;
}

/* ***********************************************************************************************
 * ***********************************************************************************************
 * Stub function list
 * ***********************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
const STUB_FUNCTIONS stub_jitter = {
    .new_fn = stub_jitter_new,
    .free_fn = stub_jitter_free,
    .gather_fn = stub_jitter_gather,
    .get_name_fn = stub_jitter_get_name,
    .get_state_fn = stub_jitter_get_state,
};

 /* **********************************************************************************************
 * ***********************************************************************************************
 * Stub parameters from 'kpepmodule.cnf'
 * ***********************************************************************************************
 * ***********************************************************************************************/

static KPEP_RESULT load_params(void* prov_ctx, JITTER_CTX *ctx)
{
    const char *osr_str = NULL;
    const char *bsize_str = NULL;
    const char *bcount_str = NULL;

    if (!prov_ctx)
        return KPEP_R_NULL_ARG;

    OSSL_PARAM params[4], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        KPEP_PROV_PARAM_SEED_JITTER"."KPEP_PROV_PARAM_SEED_BLOCK_SIZE,
        (char **) &bsize_str,
        sizeof(bsize_str));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        KPEP_PROV_PARAM_SEED_JITTER"."KPEP_PROV_PARAM_SEED_BLOCK_COUNT,
        (char **) &bcount_str,
        sizeof(bcount_str));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        KPEP_PROV_PARAM_SEED_JITTER_OVERSAMPLE,
        (char **) &osr_str,
        sizeof(osr_str));
    *p = OSSL_PARAM_construct_end();

    if (!kpep_get_core_params(prov_ctx, params)) {
        LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_CONFIG_LOOKUP_FAILURE);
        return KPEP_R_CONFIG_LOOKUP_FAILURE;
    }

    // Oversample Rate
    if (osr_str) {
        ctx->osr = atoi(osr_str);
        if (errno) {
            LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_CONFIG_PARAMETER_INVALID);
            return KPEP_R_CONFIG_PARAMETER_INVALID;
        }
    }
    else {
        if (!prov_ctx) {
            ctx->osr = 4;  // Set from ESV
        }
        else {
            LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_CONFIG_PARAMETER_MISSING);
            return KPEP_R_CONFIG_PARAMETER_MISSING;
        }
    }

    // Block Size
    if (bsize_str) {
        ctx->block_size = atoi(bsize_str);
        if (errno) {
            LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_CONFIG_PARAMETER_INVALID);
            return KPEP_R_CONFIG_PARAMETER_INVALID;
        }
    }
    else {
        if (!prov_ctx) {
            ctx->block_size = 64;
        }
        else {
            LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_CONFIG_PARAMETER_MISSING);
            return KPEP_R_CONFIG_PARAMETER_MISSING;
        }
    }

    // Block Count
    if (bcount_str) {
        ctx->block_count = atoi(bcount_str);
        if (errno) {
            LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_CONFIG_PARAMETER_INVALID);
            return KPEP_R_CONFIG_PARAMETER_INVALID;
        }
    }
    else {
        if (!prov_ctx) {
            ctx->block_count = 1;
        }
        else {
            LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_CONFIG_PARAMETER_MISSING);
            return KPEP_R_CONFIG_PARAMETER_MISSING;
        }
    }

    return KPEP_R_SUCCESS;
}
