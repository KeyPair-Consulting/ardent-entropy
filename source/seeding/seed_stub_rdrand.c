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
#include "ardent/ardent_cpuinfo.h"
#include "rdcpu_toolbox.h"

#include "openssl/params.h"
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>

/* ************************************************************************************************
 * ***********************************************************************************************
 * Definitions, declarations, and context structure
 * ***********************************************************************************************
 * ***********************************************************************************************/

#define MODULE_NAME "SEED-RDRAND"
static const char *base_name = "RDRAND";

typedef struct {
    COMMON_STUB_INFO  // See seed_context.h

    // Source-specific parameters
    uint32_t retry_count;
    CPU_TYPE cpu_type;
} RDRAND_CTX;

static ARDENT_RESULT load_params(void* prov_ctx, RDRAND_CTX *ctx);

/* ************************************************************************************************
 * ***********************************************************************************************
 * Stub functions
 * ***********************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
void stub_rdrand_free(void *stub_ctx)
{
    RDRAND_CTX *ctx = (RDRAND_CTX *)stub_ctx;

    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }

    if (ctx) {
        ardent_free(ctx);
    }
    ardent_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'rdrand' shutdown successful");
}

EXPORT_VISIBILITY_HIDDEN
void* stub_rdrand_new(void* prov_ctx, uint32_t idx, ARDENT_RESULT *errnum)
{
    RDRAND_CTX *ctx;
    ARDENT_RESULT result;
    size_t full_entropy_sz;
    uint32_t len;

    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }

#ifdef FIPS_OPTEST
    {
        const char* debug = getenv(ENV_OPTEST_SEED_RDRAND_NEW);
        if (debug) {
            LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdrand' failed startup (optest)");
            if (errnum) *errnum = ARDENT_R_FIPS_OPTEST;
            return NULL;
        }
    }
#endif

    // Allocate for source context
    ctx = ardent_zalloc(sizeof(RDRAND_CTX));
    if (ctx == NULL) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdrand' failed startup (malloc)");
        if (errnum) *errnum = ARDENT_R_MALLOC_FAIL;
        return NULL;
    }

    // Check for CPU support
    if (check_is_intel()) {
        ctx->cpu_type = CPU_INTEL;
    }
    else if (check_is_amd()) {
        ctx->cpu_type = CPU_AMD;
    }
    else {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdrand' failed startup (cpuid)");
        if (errnum) *errnum = ARDENT_R_SEED_INIT_FAIL;
        goto err;
    }
    if (!check_rdrand_support()) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdrand' failed startup (no cpu support)");
        if (errnum) *errnum = ARDENT_R_SEED_INIT_FAIL;
        goto err;
    }
    
    // Pull runtime configuration from params
    if ((result = load_params(prov_ctx, ctx)) != ARDENT_R_SUCCESS) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdrand' failed startup (load params)");
        if (errnum) *errnum = result;
        goto err;
    }

    // Set entropy factors
    full_entropy_sz = ctx->block_size * ctx->block_count;
    if (full_entropy_sz < ARDENT_SECURITY_STRENGTH_BITS) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdrand' failed startup (block size check)");
        if (errnum) *errnum = ARDENT_R_INVALID_ARG;
        goto err;
    }
    ctx->full_entropy = (ARDENT_SECURITY_STRENGTH_BITS == full_entropy_sz);
    if (!ctx->full_entropy) {
        ctx->entropy_per_bit = (double) ARDENT_SECURITY_STRENGTH_BITS / (double) full_entropy_sz;
    }
    
    // Name
    len = snprintf(ctx->name, sizeof(ctx->name),
                "%s (%s)",
                base_name,
                (ctx->cpu_type==CPU_AMD)  ?"AMD":
                (ctx->cpu_type==CPU_INTEL)?"Intel":
                                           "Unknown");
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
    // NOTHING!

    // Start initialized
    if (ctx->full_entropy)
        ardent_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'rdrand' startup successful (full entropy)");
    else
        ardent_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'rdrand' startup successful (%.6f ent-per-bit)", ctx->entropy_per_bit);
    ctx->state = ARDENT_RAND_STATE_READY;

    // Set initial state for profiling
    ctx->prof_min = UINT32_MAX;

    return ctx;

err:
    ardent_cleanse(ctx, sizeof(RDRAND_CTX));
    return NULL;
}

EXPORT_VISIBILITY_HIDDEN
ARDENT_RESULT stub_rdrand_gather(void *stub_ctx, unsigned char *out, size_t *out_len, size_t nbits)
{
    RDRAND_CTX *ctx = (RDRAND_CTX *)stub_ctx;
    ARDENT_RESULT rv = ARDENT_R_SUCCESS;
    size_t gather_bits, gather_bytes;
    uint32_t start_us;
    int result;

    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }

#ifdef FIPS_OPTEST
    {
        const char* debug;
        debug = getenv(ENV_OPTEST_SEED_RDRAND_GATHER);
        if (debug) {
            LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdrand' gather failed (optest)");
            return ARDENT_R_FIPS_OPTEST;
        }
        debug = getenv(ENV_OPTEST_SEED_RDRAND_FATAL);
        if (debug) {
            LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdrand' gather failed (optest-fatal)");
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

    // Get the entropy from CPU (with profiling)
    if (ardent_profile_enabled) {
        start_us = seed_stub_profile_now_us();
    }
    result = rdrand_get_bytes_step(gather_bytes, out, ctx->retry_count);
    if (ardent_profile_enabled) {
        seed_stub_profile_update((SEED_STUB_INFO *)ctx, seed_stub_profile_now_us() - start_us,
            result ? gather_bytes : 0);
    }
    if (!result) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdrand' gather failed");
        goto err;
    }

    // Success
    *out_len = gather_bytes;
    return ARDENT_R_SUCCESS;

err:
    // If no error already set, assume a general error
    if (!rv) {
        LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_ERROR_RETRIEVING_ENTROPY);
        rv = ARDENT_R_ERROR_RETRIEVING_ENTROPY;
    }

    // Zeroize
    memset(out, 0, *out_len);
    *out_len = 0;

    return rv;
}

EXPORT_VISIBILITY_HIDDEN
uint32_t  stub_rdrand_get_state(void* stub_ctx)
{
    RDRAND_CTX *ctx = (RDRAND_CTX *)stub_ctx;
    if (!ctx)
        return ARDENT_RAND_STATE_UNINITIALISED; // Value 0
    return ctx->state;
}

EXPORT_VISIBILITY_HIDDEN
const char* stub_rdrand_get_name(void* stub_ctx) 
{
    RDRAND_CTX *ctx = (RDRAND_CTX *)stub_ctx;
    if (!ctx) {
        ardent_log(LOG_LVL_WARN, MODULE_NAME, "get_name(rdrand) called with NULL context (should not happen)");
        return NULL;
    }   
    return ctx->name;
}

/* ***********************************************************************************************
 * ***********************************************************************************************
 * Stub function list
 * ***********************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
const STUB_FUNCTIONS stub_rdrand = {
    .new_fn = stub_rdrand_new,
    .free_fn = stub_rdrand_free,
    .gather_fn = stub_rdrand_gather,
    .get_name_fn = stub_rdrand_get_name,
    .get_state_fn = stub_rdrand_get_state,
};

/* ***********************************************************************************************
 * ***********************************************************************************************
 * Stub parameters from 'ardentmodule.cnf'
 * ***********************************************************************************************
 * ***********************************************************************************************/

static ARDENT_RESULT load_params(void* prov_ctx, RDRAND_CTX *ctx)
{
    const char *bsize_str = NULL;
    const char *bcount_str = NULL;
    const char *retry_str = NULL;

    if (!prov_ctx)
        return ARDENT_R_NULL_ARG;

    OSSL_PARAM params[4], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        ARDENT_PROV_PARAM_SEED_RDRAND"."ARDENT_PROV_PARAM_SEED_BLOCK_SIZE,
        (char **) &bsize_str,
        sizeof(bsize_str));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        ARDENT_PROV_PARAM_SEED_RDRAND"."ARDENT_PROV_PARAM_SEED_BLOCK_COUNT,
        (char **) &bcount_str,
        sizeof(bcount_str));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        ARDENT_PROV_PARAM_SEED_RDRAND"."ARDENT_PROV_PARAM_SEED_RETRY_COUNT,
        (char **) &retry_str,
        sizeof(retry_str));
    *p = OSSL_PARAM_construct_end();

    if (!ardent_get_core_params(prov_ctx, params)) {
        LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_CONFIG_LOOKUP_FAILURE);
        return ARDENT_R_CONFIG_LOOKUP_FAILURE;
    }

    // Block Size
    if (bsize_str) {
        if (!parse_uint32(bsize_str, &ctx->block_size) || ctx->block_size == 0) {
            LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_CONFIG_PARAMETER_INVALID);
            return ARDENT_R_CONFIG_PARAMETER_INVALID;
        }
    }
    else {
        LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_CONFIG_PARAMETER_MISSING);
        return ARDENT_R_CONFIG_PARAMETER_MISSING;
    }

    // Block Count
    if (bcount_str) {
        if (!parse_uint32(bcount_str, &ctx->block_count) || ctx->block_count == 0) {
            LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_CONFIG_PARAMETER_INVALID);
            return ARDENT_R_CONFIG_PARAMETER_INVALID;
        }
    }
    else {
        LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_CONFIG_PARAMETER_MISSING);
        return ARDENT_R_CONFIG_PARAMETER_MISSING;
    }

    // Retry Count (optional)
    if (retry_str) {
        if (!parse_uint32(retry_str, &ctx->retry_count) || ctx->retry_count == 0) {
            LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_CONFIG_PARAMETER_INVALID);
            return ARDENT_R_CONFIG_PARAMETER_INVALID;
        }
    }
    else {
        ctx->retry_count = RDRAND_RETRY_DEFAULT;
    }
    
    return ARDENT_R_SUCCESS;
}

