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
#include "seed_context.h"
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

#define MODULE_NAME "SEED-RDRAND"

typedef struct {
    COMMON_STUB_INFO  // See seed_context.h

    // Source-specific parameters
    uint32_t retry_count;
    CPU_TYPE type;
} RDRAND_CTX;

static KPEP_RESULT load_params(void* prov_ctx, RDRAND_CTX *ctx);

static const char *base_name = "RDRAND";

/* ************************************************************************************************
 * ***********************************************************************************************
 * Stub functions
 * ***********************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
void stub_rdrand_free(void *stub_ctx)
{
    RDRAND_CTX *ctx = (RDRAND_CTX *)stub_ctx;

    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif

    if (ctx) {
        kpep_free(ctx);
    }
    kpep_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'rdrand' shutdown successful");
}

EXPORT_VISIBILITY_HIDDEN
void* stub_rdrand_new(void* prov_ctx, uint8_t idx, KPEP_RESULT *errnum)
{
    RDRAND_CTX *ctx;
    KPEP_RESULT result;
    size_t full_entropy_sz;

    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif

#ifdef FIPS_OPTEST
    {
        const char* debug = getenv(ENV_OPTEST_SEED_RDRAND_NEW);
        if (debug) {
            LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdrand' failed startup (optest)");
            if (errnum) *errnum = KPEP_R_FIPS_OPTEST;
            return NULL;
        }
    }
#endif

    // Allocate for source context
    ctx = kpep_zalloc(sizeof(RDRAND_CTX));
    if (ctx == NULL) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdrand' failed startup (malloc)");
        if (errnum) *errnum = KPEP_R_MALLOC_FAIL;
        return NULL;
    }

    // Check for CPU support
    if (check_is_intel()) {
        ctx->type = CPU_INTEL;
    }
    else if (check_is_amd()) {
        ctx->type = CPU_AMD;
    }
    else {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdrand' failed startup (cpuid)");
        if (errnum) *errnum = KPEP_R_MALLOC_FAIL;
        kpep_free(ctx);
        return NULL;
    }
    if (!check_rdrand_support()) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdrand' failed startup (no cpu support)");
        if (errnum) *errnum = KPEP_R_SEED_NO_CPU_SUPPORT;
        kpep_free(ctx);
        return NULL;
    }
    
    // Pull runtime configuration from params
    if ((result = load_params(prov_ctx, ctx)) != KPEP_R_SUCCESS) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdrand' failed startup (load params)");
        if (errnum) *errnum = result;
        kpep_cleanse(ctx, sizeof(RDRAND_CTX));
        return NULL;        
    }

    // Set entropy factors
    full_entropy_sz = ctx->block_size * ctx->block_count;
    if (full_entropy_sz < KPEP_SECURITY_STRENGTH_BITS) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdrand' failed startup (block size check)");
        kpep_cleanse(ctx, sizeof(RDRAND_CTX));
        if (errnum) *errnum = KPEP_R_INVALID_ARG;
        return NULL;        
    }
    ctx->full_entropy = (KPEP_SECURITY_STRENGTH_BITS == full_entropy_sz);
    if (!ctx->full_entropy) {
        ctx->entropy_per_bit = (double) KPEP_SECURITY_STRENGTH_BITS / (double) full_entropy_sz;
    }
    
    // Initialize source
    // NOTHING!

    // Start initialized
    if (ctx->full_entropy)
        kpep_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'rdrand' startup successful (full entropy)");
    else
        kpep_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'rdrand' startup successful (%.6f ent-per-bit)", ctx->entropy_per_bit);

    ctx->state = KPEP_RAND_STATE_READY;
    return ctx;
}

EXPORT_VISIBILITY_HIDDEN
KPEP_RESULT stub_rdrand_gather(void *stub_ctx, unsigned char *out, size_t *out_len, size_t nbits)
{
    RDRAND_CTX *ctx = (RDRAND_CTX *)stub_ctx;
    KPEP_RESULT rv = KPEP_R_SUCCESS;
    size_t gather_sz, gather_ovf;

    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif

#ifdef FIPS_OPTEST
    {
        const char* debug;
        debug = getenv(ENV_OPTEST_SEED_RDRAND_GATHER);
        if (debug) {
            LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdrand' gather failed (optest)");
            return KPEP_R_FIPS_OPTEST;
        }
        debug = getenv(ENV_OPTEST_SEED_RDRAND_FATAL);
        if (debug) {
            LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdrand' gather failed (optest-fatal)");
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
    gather_sz = (ctx->full_entropy)?nbits:(size_t) (nbits / ctx->entropy_per_bit);
    gather_ovf = (gather_sz % ctx->block_size);
    if (gather_ovf)
        gather_sz += (ctx->block_size - gather_ovf);
    gather_sz = gather_sz>>3;  // Bits to bytes

    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s %lu -> %lu\n", MODULE_NAME, out?"byte":"size", nbits, gather_sz<<3);
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
    if (ctx->state != KPEP_RAND_STATE_READY) {
        LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_SEED_NOT_READY);
        return KPEP_R_SEED_NOT_READY;
    }

    // Get the entropy from CPU
    if (!rdrand_get_bytes_step(*out_len, out, ctx->retry_count)) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'rdrand' gather failed (rdrand)");
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

    // Permanent failure or too many intermittent failures
    ctx->state = KPEP_RAND_STATE_ERROR;
    return rv;
}

EXPORT_VISIBILITY_HIDDEN
uint32_t  stub_rdrand_get_state(void* stub_ctx)
{
    RDRAND_CTX *ctx = (RDRAND_CTX *)stub_ctx;
    if (!ctx)
        return KPEP_RAND_STATE_UNINITIALISED; // Value 0
    return ctx->state;
}

EXPORT_VISIBILITY_HIDDEN
const char* stub_rdrand_get_name(void* stub_ctx) 
{
    RDRAND_CTX *ctx = (RDRAND_CTX *)stub_ctx;
    if (!ctx) {
        kpep_log(LOG_LVL_WARN, MODULE_NAME, "get_name(rdrand) called with NULL context (should not happen)");
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
 * Stub parameters from 'kpepmodule.cnf'
 * ***********************************************************************************************
 * ***********************************************************************************************/

static KPEP_RESULT load_params(void* prov_ctx, RDRAND_CTX *ctx)
{
    const char *bsize_str = NULL;
    const char *bcount_str = NULL;
    const char *retry_str = NULL;
    const char *valid_str = NULL;

    if (prov_ctx) {
        OSSL_PARAM params[5], *p = params;
        *p++ = OSSL_PARAM_construct_utf8_ptr(
            KPEP_PROV_PARAM_SEED_RDRAND"."KPEP_PROV_PARAM_SEED_VALIDATED,
            (char **) &valid_str,
            sizeof(valid_str));
        *p++ = OSSL_PARAM_construct_utf8_ptr(
            KPEP_PROV_PARAM_SEED_RDRAND"."KPEP_PROV_PARAM_SEED_BLOCK_SIZE,
            (char **) &bsize_str,
            sizeof(bsize_str));
        *p++ = OSSL_PARAM_construct_utf8_ptr(
            KPEP_PROV_PARAM_SEED_RDRAND"."KPEP_PROV_PARAM_SEED_BLOCK_COUNT,
            (char **) &bcount_str,
            sizeof(bcount_str));
        *p++ = OSSL_PARAM_construct_utf8_ptr(
            KPEP_PROV_PARAM_SEED_RDRAND"."KPEP_PROV_PARAM_SEED_RETRY_COUNT,
            (char **) &retry_str,
            sizeof(retry_str));
        *p = OSSL_PARAM_construct_end();

        if (!kpep_get_core_params(prov_ctx, params)) {
            LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_CONFIG_LOOKUP_FAILURE);
            return KPEP_R_CONFIG_LOOKUP_FAILURE;
        }
    }
    else {
        bsize_str = getenv(ENV_SEED_RDRAND_BLOCK_SIZE);
        bcount_str = getenv(ENV_SEED_RDRAND_BLOCK_COUNT);
        retry_str = getenv(ENV_SEED_RDRAND_RETRY_COUNT);
    }

    // Name
    sprintf(ctx->name, "%s (%s)", base_name, (ctx->type==CPU_AMD)?"AMD":
                                             (ctx->type==CPU_INTEL)?"Intel":
                                             "Unknown");
    if (valid_str && strncmp(valid_str, "0", 1)) {
        sprintf(ctx->name+strlen(ctx->name), " [%s]", valid_str);
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
        ctx->retry_count = RDRAND_RETRY_DEFAULT;
    }
    
    return KPEP_R_SUCCESS;
}

