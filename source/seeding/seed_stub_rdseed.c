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
#include "kpep/kpep_cpuinfo.h"
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

#define MODULE_NAME "SEED-RDSEED"
static const char *base_name = "RDSEED";

typedef struct {
    COMMON_STUB_INFO  // See seed_context.h

    // Source-specific parameters
    uint32_t retry_count;
    CPU_TYPE cpu_type;
} RDSEED_CTX;

static KPEP_RESULT load_params(void* prov_ctx, RDSEED_CTX *ctx);

/* ************************************************************************************************
 * ***********************************************************************************************
 * Stub functions
 * ***********************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
void stub_rdseed_free(void *stub_ctx)
{
    RDSEED_CTX *ctx = (RDSEED_CTX *)stub_ctx;

    if (kpep_trace_seed_enabled) {
        TRACE_START;
    }

    if (ctx) {
        kpep_free(ctx);
    }
    kpep_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'rdseed' shutdown successful");
}

EXPORT_VISIBILITY_HIDDEN
void* stub_rdseed_new(void* prov_ctx, uint32_t idx, KPEP_RESULT *errnum)
{
    RDSEED_CTX *ctx;
    KPEP_RESULT result;
    size_t full_entropy_sz;
    uint32_t len;

    if (kpep_trace_seed_enabled) {
        TRACE_START;
    }

#ifdef FIPS_OPTEST
    {
        const char* debug = getenv(ENV_OPTEST_SEED_RDSEED_NEW);
        if (debug) {
            LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdseed' failed startup (optest)");
            if (errnum) *errnum = KPEP_R_FIPS_OPTEST;
            return NULL;
        }
    }
#endif

    // Allocate for source context
    ctx = kpep_zalloc(sizeof(RDSEED_CTX));
    if (ctx == NULL) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdseed' failed startup (malloc)");
        if (errnum) *errnum = KPEP_R_MALLOC_FAIL;
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
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdseed' failed startup (cpuid)");
        if (errnum) *errnum = KPEP_R_MALLOC_FAIL;
        kpep_free(ctx);
        return NULL;
    }
    if (!check_rdseed_support()) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdseed' failed startup (no cpu support)");
        if (errnum) *errnum = KPEP_R_SEED_NO_CPU_SUPPORT;
        kpep_free(ctx);
        return NULL;
    }
    
    // Pull runtime configuration from params
    if ((result = load_params(prov_ctx, ctx)) != KPEP_R_SUCCESS) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdseed' failed startup (load params)");
        if (errnum) *errnum = result;
        kpep_cleanse(ctx, sizeof(RDSEED_CTX));
        return NULL;        
    }

    // Set entropy factors
    full_entropy_sz = ctx->block_size * ctx->block_count;
    if (full_entropy_sz < KPEP_SECURITY_STRENGTH_BITS) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdseed' failed startup (block size check)");
        kpep_cleanse(ctx, sizeof(RDSEED_CTX));
        if (errnum) *errnum = KPEP_R_INVALID_ARG;
        return NULL;        
    }
    ctx->full_entropy = (KPEP_SECURITY_STRENGTH_BITS == full_entropy_sz);
    if (!ctx->full_entropy) {
        ctx->entropy_per_bit = (double) KPEP_SECURITY_STRENGTH_BITS / (double) full_entropy_sz;
    }

    // Name
    len = snprintf(ctx->name,
                sizeof(ctx->name),
                "%s (%s)",
                base_name,
                (ctx->cpu_type==CPU_AMD)  ?"AMD":
                (ctx->cpu_type==CPU_INTEL)?"Intel":
                                           "Unknown");
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
    // NOTHING!

    // Start initialized
    if (ctx->full_entropy)
        kpep_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'rdseed' startup successful (full entropy)");
    else
        kpep_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'rdseed' startup successful (%.6f ent-per-bit)", ctx->entropy_per_bit);

    ctx->state = KPEP_RAND_STATE_READY;
    return ctx;
}

EXPORT_VISIBILITY_HIDDEN
KPEP_RESULT stub_rdseed_gather(void *stub_ctx, unsigned char *out, size_t *out_len, size_t nbits)
{
    RDSEED_CTX *ctx = (RDSEED_CTX *)stub_ctx;
    KPEP_RESULT rv = KPEP_R_SUCCESS;
    size_t gather_bits, gather_bytes;
    uint32_t start_us;
    int result;

    if (kpep_trace_seed_enabled) {
        TRACE_START;
    }

#ifdef FIPS_OPTEST
    {
        const char* debug;
        debug = getenv(ENV_OPTEST_SEED_RDSEED_GATHER);
        if (debug) {
            LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdseed' gather failed (optest)");
            return KPEP_R_FIPS_OPTEST;
        }
        debug = getenv(ENV_OPTEST_SEED_RDSEED_FATAL);
        if (debug) {
            LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdseed' gather failed (optest-fatal)");
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

    // Get the entropy from CPU (with profiling)
    if (kpep_profile_enabled) {
        start_us = seed_stub_profile_now_us();
    }
    result = rdseed_get_bytes_step(gather_bytes, out, ctx->retry_count);
    if (kpep_profile_enabled) {
        seed_stub_profile_update((SEED_STUB_INFO *)ctx, seed_stub_profile_now_us() - start_us);
    }
    if (!result) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdseed' gather failed (rdseed)");
        goto err;
    }

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

    // Permanent failure or too many intermittent failures
    ctx->state = KPEP_RAND_STATE_ERROR;
    return rv;
}

EXPORT_VISIBILITY_HIDDEN
uint32_t  stub_rdseed_get_state(void* stub_ctx)
{
    RDSEED_CTX *ctx = (RDSEED_CTX *)stub_ctx;
    if (!ctx)
        return KPEP_RAND_STATE_UNINITIALISED; // Value 0
    return ctx->state;
}

EXPORT_VISIBILITY_HIDDEN
const char* stub_rdseed_get_name(void* stub_ctx) 
{
    RDSEED_CTX *ctx = (RDSEED_CTX *)stub_ctx;
    if (!ctx) {
        kpep_log(LOG_LVL_WARN, MODULE_NAME, "get_name(rdseed) called with NULL context (should not happen)");
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
const STUB_FUNCTIONS stub_rdseed = {
    .new_fn = stub_rdseed_new,
    .free_fn = stub_rdseed_free,
    .gather_fn = stub_rdseed_gather,
    .get_name_fn = stub_rdseed_get_name,
    .get_state_fn = stub_rdseed_get_state,
};

/* ***********************************************************************************************
 * ***********************************************************************************************
 * Stub parameters from 'kpepmodule.cnf'
 * ***********************************************************************************************
 * ***********************************************************************************************/

static KPEP_RESULT load_params(void* prov_ctx, RDSEED_CTX *ctx)
{
    const char *bsize_str = NULL;
    const char *bcount_str = NULL;
    const char *retry_str = NULL;

    if (!prov_ctx)
        return KPEP_R_NULL_ARG;

    OSSL_PARAM params[4], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        KPEP_PROV_PARAM_SEED_RDSEED"."KPEP_PROV_PARAM_SEED_BLOCK_SIZE,
        (char **) &bsize_str,
        sizeof(bsize_str));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        KPEP_PROV_PARAM_SEED_RDSEED"."KPEP_PROV_PARAM_SEED_BLOCK_COUNT,
        (char **) &bcount_str,
        sizeof(bcount_str));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        KPEP_PROV_PARAM_SEED_RDSEED"."KPEP_PROV_PARAM_SEED_RETRY_COUNT,
        (char **) &retry_str,
        sizeof(retry_str));
    *p = OSSL_PARAM_construct_end();

    if (!kpep_get_core_params(prov_ctx, params)) {
        LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_CONFIG_LOOKUP_FAILURE);
        return KPEP_R_CONFIG_LOOKUP_FAILURE;
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
        LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_CONFIG_PARAMETER_MISSING);
        return KPEP_R_CONFIG_PARAMETER_MISSING;
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
        LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_CONFIG_PARAMETER_MISSING);
        return KPEP_R_CONFIG_PARAMETER_MISSING;
    }

    // Retry Count (optional)
    if (retry_str) {
        ctx->retry_count = atoi(retry_str);
        if (errno) {
            LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_CONFIG_PARAMETER_INVALID);
            return KPEP_R_CONFIG_PARAMETER_INVALID;
        }
    }
    else {
        ctx->retry_count = RDSEED_RETRY_DEFAULT;
    }

    return KPEP_R_SUCCESS;
}

