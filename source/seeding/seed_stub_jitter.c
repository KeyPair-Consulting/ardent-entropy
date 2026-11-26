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

#include "ardent/ardent.h"
#include "ardent/ardent_names.h"
#include "ardent/ardent_seed_stub.h"
#include "seed_sources.h"

#include "openssl/params.h"
#include "jitterentropy.h"

//ARDENT: For Debugging "__func__"
#include <stdio.h>

/* ***********************************************************************************************
 * ***********************************************************************************************
 * Definitions, declarations, and context structure
 * ***********************************************************************************************
 * ***********************************************************************************************/

// Required flags, per ESV E239
#define JENT_ARDENT_FLAGS JENT_FORCE_FIPS | JENT_DISABLE_INTERNAL_TIMER

#define JITTER_MAX_NUM_TRIES 3

#define MODULE_NAME "SEED-JITTER"

typedef struct {
    COMMON_STUB_INFO  // See seed_context.h

    // Source-specific parameters
    unsigned int osr; 
} JITTER_CTX;

static ARDENT_RESULT load_params(void* prov_ctx, JITTER_CTX *ctx);

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
    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }

    ardent_cleanse(ctx, sizeof(JITTER_CTX));
    ardent_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'jitter' shutdown successful");
}
 
EXPORT_VISIBILITY_HIDDEN
void* stub_jitter_new(void* prov_ctx, uint32_t idx, ARDENT_RESULT *errnum)
{
    JITTER_CTX *ctx;
    ARDENT_RESULT result;
    size_t full_entropy_sz;
    int ret;
    uint32_t len;

    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }

#ifdef FIPS_OPTEST
    {
        const char* debug = getenv(ENV_OPTEST_SEED_JITTER_NEW);
        if (debug) {
            LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'jitter' failed startup (optest)");
            if (errnum) *errnum = ARDENT_R_FIPS_OPTEST;
            return NULL;
        }
    }
#endif

    // Allocate for source context
    ctx = ardent_zalloc(sizeof(JITTER_CTX));
    if (ctx == NULL) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'jitter' failed startup (malloc)");
        if (errnum) *errnum = ARDENT_R_MALLOC_FAIL;
        return NULL;
    }

    // Pull runtime configuration from params
    if ((result = load_params(prov_ctx, ctx)) != ARDENT_R_SUCCESS) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'jitter' failed startup (load params)");
        if (errnum) *errnum = result;
        goto err;
    }

    // Set entropy factors
    full_entropy_sz = ctx->block_size * ctx->block_count;
    if (full_entropy_sz < ARDENT_SECURITY_STRENGTH_BITS) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'jitter' failed startup (block size check)");
        if (errnum) *errnum = ARDENT_R_INVALID_ARG;
        goto err;
    }
    ctx->full_entropy = (ARDENT_SECURITY_STRENGTH_BITS == full_entropy_sz);
    if (!ctx->full_entropy)
        ctx->entropy_per_bit = (double) ARDENT_SECURITY_STRENGTH_BITS / (double) full_entropy_sz;

    // Name
    len = snprintf(ctx->name, sizeof(ctx->name),
                "%s",
                base_name);
    if (len < 0) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Unable to format source name");
        if (errnum) *errnum = ARDENT_R_SEED_INIT_FAIL;
        goto err;
    }
    if ((size_t)len >= sizeof(ctx->name)) {
        LOG_FORMATTED_ERROR(MODULE_NAME,
                            "Seed source name '%s' truncated",
                            base_name);
    }

    // Initialize source
    if ((ret = jent_entropy_init_ex(ctx->osr, JENT_ARDENT_FLAGS)) != 0) {
        LOG_FORMATTED_ERROR(MODULE_NAME, "Seed source 'jitter' failed startup (library); errnum (%d)", ret);
        if (errnum) *errnum = ARDENT_R_SEED_INIT_FAIL;
        goto err;
    }

    // Start initialized
    if (ctx->full_entropy)
        ardent_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'jitter' startup successful (full entropy)");
    else
        ardent_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'jitter' startup successful (%.6f ent-per-bit)", ctx->entropy_per_bit);

    ctx->state = ARDENT_RAND_STATE_READY;

    // Set initial state for profiling
    ctx->prof_min = UINT32_MAX;

    return ctx;

err:
    ardent_cleanse(ctx, sizeof(JITTER_CTX));
    return NULL;
}

EXPORT_VISIBILITY_HIDDEN
ARDENT_RESULT stub_jitter_gather(void *stub_ctx, unsigned char *out, size_t *out_len, size_t nbits)
{
    JITTER_CTX *ctx = (JITTER_CTX *)stub_ctx;
    ARDENT_RESULT rv = ARDENT_R_SUCCESS;
    size_t gather_bits, gather_bytes;

    struct rand_data *jitter_ec = NULL;
    ssize_t result = 0;
    size_t num_tries;
    uint32_t start_us;

    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }

#ifdef FIPS_OPTEST
    {
        const char* debug;
        debug = getenv(ENV_OPTEST_SEED_JITTER_GATHER);
        if (debug) {
            return ARDENT_R_FIPS_OPTEST;
        }
        debug = getenv(ENV_OPTEST_SEED_JITTER_FATAL);
        if (debug) {
            ctx->state = ARDENT_RAND_STATE_ERROR;
            return ARDENT_R_SEED_FATAL_ERROR;
        }
    }
#endif

    if (!nbits)
        return ARDENT_R_SUCCESS;

    // Validate context
    if (!ctx || !out || !out_len) {
        LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_NULL_ARG);
        return ARDENT_R_NULL_ARG;
    }
    if (nbits < ARDENT_SECURITY_STRENGTH_BITS) {
        LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_INVALID_ARG);
        return ARDENT_R_INVALID_ARG;
    }

    // Calculate gather size
    gather_bits = seed_get_gather_sz((SEED_STUB_INFO*)ctx, nbits);
    gather_bytes = (gather_bits + 7) >> 3;
    
    if (ardent_trace_seed_enabled) {
        ardent_trace_fmt(MODULE_NAME, "%s %lu -> %lu", out?"byte":"size", nbits, gather_bits);
    }

    // Check for adequate size
    if (*out_len < gather_bytes) {
        LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_SEED_BUFFER_TOO_SMALL);
        return ARDENT_R_SEED_BUFFER_TOO_SMALL;
    }

    // Check state
    if (ctx->state != ARDENT_RAND_STATE_READY) {
        LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_SEED_NOT_READY);
        return ARDENT_R_SEED_NOT_READY;
    }

    // Retry intermittent failures, then give up
    if (ardent_profile_enabled) {
        start_us = seed_stub_profile_now_us();
    }
    for (num_tries = 0; num_tries < JITTER_MAX_NUM_TRIES; num_tries++) {
        /* Allocate a fresh collector */
        jitter_ec = jent_entropy_collector_alloc(ctx->osr, JENT_ARDENT_FLAGS);
        if (jitter_ec == NULL)
            continue;

        /* Do not use _safe API as per typical security policies */
        result = jent_read_entropy(jitter_ec, (char *) out, gather_bytes);
        jent_entropy_collector_free(jitter_ec);

        /* Permanent Failure
         * https://github.com/smuellerDD/jitterentropy-library/blob/master/doc/jitterentropy.3#L234
         */
        if (result < -5) {
            LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_SEED_FATAL_ERROR);
            rv = ARDENT_R_SEED_FATAL_ERROR;
            break;
        }

        // Success
        if (result >= 0 && (size_t)result == gather_bytes)  {
            if (ardent_profile_enabled) {
                seed_stub_profile_update((SEED_STUB_INFO *)ctx, seed_stub_profile_now_us() - start_us,
                    (uint32_t)result);
            }
            *out_len = gather_bytes;
            return ARDENT_R_SUCCESS;
        }
    }
    
    // We are going to be entering a permanent error state, but it's probaby a good idea to still 
    // grab the profiling information.
    if (ardent_profile_enabled) {
        seed_stub_profile_update((SEED_STUB_INFO *)ctx, seed_stub_profile_now_us() - start_us, 0);
    }

    // If no error already set, assume a general error
    if (!rv)
        rv = ARDENT_R_ERROR_RETRIEVING_ENTROPY;

    // Zeroize
    memset(out, 0, *out_len);
    *out_len = 0;

    // Set state to ERROR only if fatal error
    if (rv == ARDENT_R_SEED_FATAL_ERROR) {
        ctx->state = ARDENT_RAND_STATE_ERROR;
    }
    return rv;
}

EXPORT_VISIBILITY_HIDDEN
uint32_t stub_jitter_get_state(void* stub_ctx)
{
    JITTER_CTX *ctx = (JITTER_CTX *)stub_ctx;
    if (!ctx) 
        return ARDENT_RAND_STATE_UNINITIALISED; // Value 0
    return ctx->state;
}

EXPORT_VISIBILITY_HIDDEN
const char* stub_jitter_get_name(void* stub_ctx) 
{
    JITTER_CTX *ctx = (JITTER_CTX *)stub_ctx;
    if (!ctx) {
        ardent_log(LOG_LVL_WARN, MODULE_NAME, "get_name(jitter) called with NULL context (should not happen)");
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
 * Stub parameters from 'ardentmodule.cnf'
 * ***********************************************************************************************
 * ***********************************************************************************************/

static ARDENT_RESULT load_params(void* prov_ctx, JITTER_CTX *ctx)
{
    const char *osr_str = NULL;
    const char *bsize_str = NULL;
    const char *bcount_str = NULL;

    if (!prov_ctx)
        return ARDENT_R_NULL_ARG;

    OSSL_PARAM params[4], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        ARDENT_PROV_PARAM_SEED_JITTER"."ARDENT_PROV_PARAM_SEED_BLOCK_SIZE,
        (char **) &bsize_str,
        sizeof(bsize_str));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        ARDENT_PROV_PARAM_SEED_JITTER"."ARDENT_PROV_PARAM_SEED_BLOCK_COUNT,
        (char **) &bcount_str,
        sizeof(bcount_str));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        ARDENT_PROV_PARAM_SEED_JITTER_OVERSAMPLE,
        (char **) &osr_str,
        sizeof(osr_str));
    *p = OSSL_PARAM_construct_end();

    if (!ardent_get_core_params(prov_ctx, params)) {
        LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_CONFIG_LOOKUP_FAILURE);
        return ARDENT_R_CONFIG_LOOKUP_FAILURE;
    }

    // Oversample Rate
    if (osr_str) {
        if (!parse_uint32(osr_str, &ctx->osr) || ctx->osr == 0) {
            LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_CONFIG_PARAMETER_INVALID);
            return ARDENT_R_CONFIG_PARAMETER_INVALID;
        }
    }
    else {
        if (!prov_ctx) {
            ctx->osr = 4;  // Set from ESV
        }
        else {
            LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_CONFIG_PARAMETER_MISSING);
            return ARDENT_R_CONFIG_PARAMETER_MISSING;
        }
    }

    // Block Size
    if (bsize_str) {
        if (!parse_uint32(bsize_str, &ctx->block_size) || ctx->block_size == 0) {
            LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_CONFIG_PARAMETER_INVALID);
            return ARDENT_R_CONFIG_PARAMETER_INVALID;
        }
    }
    else {
        if (!prov_ctx) {
            ctx->block_size = 64;
        }
        else {
            LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_CONFIG_PARAMETER_MISSING);
            return ARDENT_R_CONFIG_PARAMETER_MISSING;
        }
    }

    // Block Count
    if (bcount_str) {
        if (!parse_uint32(bcount_str, &ctx->block_count) || ctx->block_count == 0) {
            LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_CONFIG_PARAMETER_INVALID);
            return ARDENT_R_CONFIG_PARAMETER_INVALID;
        }
    }
    else {
        if (!prov_ctx) {
            ctx->block_count = 1;
        }
        else {
            LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_CONFIG_PARAMETER_MISSING);
            return ARDENT_R_CONFIG_PARAMETER_MISSING;
        }
    }

    return ARDENT_R_SUCCESS;
}
