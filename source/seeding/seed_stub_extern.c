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

/*  External libraries can be disabled by compilation flags */
#ifdef KPEP_DISABLE_EXTERNAL
EXPORT_VISIBILITY_HIDDEN
const STUB_FUNCTIONS stub_extern = {
    .new_fn = NULL,
    .free_fn = NULL,
    .gather_fn = NULL,
    .get_name_fn = NULL,
    .get_state_fn = NULL,
};
#else

#include "openssl/params.h"
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>

/* ************************************************************************************************
 * ***********************************************************************************************
 * Definitions, declarations, and context structure
 * ***********************************************************************************************
 * ***********************************************************************************************/

#define MODULE_NAME "SEED-EXTERN"
static const char *base_name = "EXTERNAL";

typedef struct {
    COMMON_STUB_INFO  // See seed_context.h

    // Source-specific parameters
    const char     *validated;
    const char     *filepath;
    const char     *symbol;
    STUB_FUNCTIONS *ext_stub;
    void           *ext_ctx;
    void           *hnd;
} EXTERNAL_CTX;

static KPEP_RESULT load_params(void* prov_ctx, EXTERNAL_CTX *ctx);

static const char* filename_from_pathname(EXTERNAL_CTX* ctx);

/* ************************************************************************************************
 * ***********************************************************************************************
 * Stub functions
 * ***********************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
void stub_extern_free(void *stub_ctx)
{
    EXTERNAL_CTX *ctx = (EXTERNAL_CTX *)stub_ctx;

    if (kpep_trace_seed_enabled) {
        TRACE_START;
    }

    if (ctx->hnd && dlclose(ctx->hnd)) {
        printf("DLCLOSE error: %s\n", dlerror());
    }

    kpep_cleanse(ctx, sizeof(EXTERNAL_CTX));
    kpep_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'external' shutdown successful");
}

EXPORT_VISIBILITY_HIDDEN
void* stub_extern_new(void* prov_ctx, uint32_t idx, KPEP_RESULT *errnum)
{
    EXTERNAL_CTX *ctx;
    KPEP_RESULT rv = KPEP_R_SUCCESS;
    size_t full_entropy_sz;
    size_t len;

    if (kpep_trace_seed_enabled) {
        TRACE_START;
    }

#ifdef FIPS_OPTEST
    {
        const char* debug = getenv(ENV_OPTEST_SEED_EXTERN_NEW);
        if (debug) {
            if (errnum) *errnum = KPEP_R_FIPS_OPTEST;
            return NULL;
        }
    }
#endif

    // Allocate for source context
    ctx = kpep_zalloc(sizeof(EXTERNAL_CTX));
    if (ctx == NULL) {
        LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_MALLOC_FAIL);
        if (errnum) *errnum = KPEP_R_MALLOC_FAIL;
        return NULL;
    }
    ctx->idx = idx;

    // Pull runtime configuration from params
    if ((rv = load_params(prov_ctx, ctx)) != KPEP_R_SUCCESS) {
        kpep_cleanse(ctx, sizeof(EXTERNAL_CTX));
        if (errnum) *errnum = rv;
        return NULL;        
    }

    // Set entropy factors
    full_entropy_sz = ctx->block_size * ctx->block_count;
    if (full_entropy_sz < KPEP_SECURITY_STRENGTH_BITS) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'external' failed startup (block size check)");
        kpep_cleanse(ctx, sizeof(EXTERNAL_CTX));
        if (errnum) *errnum = KPEP_R_INVALID_ARG;
        return NULL;        
    }
    ctx->full_entropy = (KPEP_SECURITY_STRENGTH_BITS == full_entropy_sz);
    if (!ctx->full_entropy)
        ctx->entropy_per_bit = (double) KPEP_SECURITY_STRENGTH_BITS / (double) full_entropy_sz;
    
    // Initialize source
    if (!ctx->filepath || !ctx->symbol) {
        goto err;
    }
    ctx->hnd = dlopen(ctx->filepath, RTLD_LAZY | RTLD_LOCAL);
    if (!ctx->hnd) {
        LOG_FORMATTED_ERROR(MODULE_NAME, "DLOPEN error: %s", dlerror());
        if (errnum) *errnum = KPEP_R_EXTERN_LOAD_FAILURE;
        goto err;
    }
    ctx->ext_stub = (STUB_FUNCTIONS*) dlsym(ctx->hnd, ctx->symbol);
    if (!ctx->ext_stub) {
        LOG_FORMATTED_ERROR(MODULE_NAME, "DLSYM error: %s", dlerror());
        if (errnum) *errnum = KPEP_R_EXTERN_LOAD_FAILURE;
        goto err;
    }

    // Call new on the stub
    ctx->ext_ctx = ctx->ext_stub->new_fn(prov_ctx, idx, errnum);
    if (!ctx->ext_ctx) {
        if (errnum) { LOG_KPEP_ERROR(MODULE_NAME, *errnum); }
        else        { kpep_log(LOG_LVL_ERR, MODULE_NAME, "'External' stub failed startup (no detail)"); }
        goto err;
    }

    // Set name
    len = snprintf(ctx->name,
        sizeof(ctx->name),
        "%s (%s)",
        base_name,
        ctx->ext_stub->get_name_fn(ctx->ext_ctx));
    if (len < 0) {
        LOG_FORMATTED_ERROR(MODULE_NAME, "Unable to format source name for ID#%d", ctx->idx);
        goto err;
    }
    if ((size_t)len >= sizeof(ctx->name)) {
        LOG_FORMATTED_ERROR(MODULE_NAME,
                            "Seed source name at ID#%d truncated",
                            ctx->idx);
    }

    // Start initialized
    kpep_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'external' startup successful");
    ctx->state = KPEP_RAND_STATE_READY;
    return ctx;

err:
    kpep_cleanse(ctx, sizeof(EXTERNAL_CTX));
    return NULL;
}

EXPORT_VISIBILITY_HIDDEN
KPEP_RESULT stub_extern_gather(void *stub_ctx, unsigned char *out, size_t *out_len, size_t nbits)
{
    EXTERNAL_CTX *ctx = (EXTERNAL_CTX *)stub_ctx;
    KPEP_RESULT rv = KPEP_R_SUCCESS;
    size_t gather_bits, gather_bytes;
    uint32_t start_us;

    if (kpep_trace_seed_enabled) {
        TRACE_START;
    }

#ifdef FIPS_OPTEST
    {
        const char* debug;
        debug = getenv(ENV_OPTEST_SEED_EXTERN_GATHER);
        if (debug) {
            LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'external' gather failed (optest)");
            return KPEP_R_FIPS_OPTEST;
        }
        debug = getenv(ENV_OPTEST_SEED_EXTERN_FATAL);
        if (debug) {
            LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'external' gather failed (optest-fatal)");
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

    // Get the entropy from the external source (with profiling)
    if (kpep_profile_enabled) {
        start_us = seed_stub_profile_now_us();
    }
    rv = ctx->ext_stub->gather_fn(ctx->ext_ctx, out, out_len, nbits);
    if (kpep_profile_enabled) {
        seed_stub_profile_update((SEED_STUB_INFO *)ctx, seed_stub_profile_now_us() - start_us);
    }
    if (rv) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'external' gather failed");
        LOG_KPEP_ERROR(MODULE_NAME, rv);
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
uint32_t stub_extern_get_state(void* stub_ctx)
{
    EXTERNAL_CTX *ctx = (EXTERNAL_CTX *)stub_ctx;
    if (kpep_trace_seed_enabled) {
        TRACE_START;
    }
    return ctx->ext_stub->get_state_fn(ctx->ext_ctx);
}

EXPORT_VISIBILITY_HIDDEN
const char* stub_extern_get_name(void* stub_ctx) 
{
    EXTERNAL_CTX *ctx = (EXTERNAL_CTX *)stub_ctx;
    if (!ctx) {
        kpep_log(LOG_LVL_WARN, MODULE_NAME, "get_name(extern) called with NULL context (should not happen)");
        return NULL;
    }   
    return ctx->name;
}

/* ***********************************************************************************************
 * ***********************************************************************************************
 * Stub Function list
 * ***********************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
const STUB_FUNCTIONS stub_extern = {
    .new_fn = stub_extern_new,
    .free_fn = stub_extern_free,
    .gather_fn = stub_extern_gather,
    .get_name_fn = stub_extern_get_name,
    .get_state_fn = stub_extern_get_state,
};

/* ***********************************************************************************************
 * ***********************************************************************************************
 * Stub parameters from 'kpepmodule.cnf'
 * ***********************************************************************************************
 * ***********************************************************************************************/

static uint32_t load_params(void* prov_ctx, EXTERNAL_CTX *ctx)
{
    const char *bsize_str = NULL;
    const char *bcount_str = NULL;
    char        bsize_key[32];
    char        bcount_key[32];
    char        filepath_key[32];
    char        symbol_key[32];

    if (!prov_ctx)
        return KPEP_R_NULL_ARG;

    OSSL_PARAM params[5], *p = params;
    sprintf(bsize_key, "%s.%d.%s", KPEP_PROV_PARAM_SEED_EXTERN, ctx->idx, KPEP_PROV_PARAM_SEED_BLOCK_SIZE);
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        bsize_key,
        (char **) &bsize_str,
        sizeof(bsize_str));
    sprintf(bcount_key, "%s.%d.%s", KPEP_PROV_PARAM_SEED_EXTERN, ctx->idx, KPEP_PROV_PARAM_SEED_BLOCK_COUNT);
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        bcount_key,
        (char **) &bcount_str,
        sizeof(bcount_str));
    sprintf(filepath_key, "%s.%d.%s", KPEP_PROV_PARAM_SEED_EXTERN, ctx->idx, KPEP_PROV_PARAM_SEED_FILEPATH);
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        filepath_key,
        (char **) &ctx->filepath,
        sizeof(ctx->filepath));
    sprintf(symbol_key, "%s.%d.%s", KPEP_PROV_PARAM_SEED_EXTERN, ctx->idx, KPEP_PROV_PARAM_SEED_FUNCTIONS);
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        symbol_key,
        (char **) &ctx->symbol,
        sizeof(ctx->symbol));
    *p = OSSL_PARAM_construct_end();

    if (!kpep_get_core_params(prov_ctx, params)) {
        LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_CONFIG_LOOKUP_FAILURE);
        return KPEP_R_CONFIG_LOOKUP_FAILURE;
    }

    // Check required 
    if (!ctx->filepath || !ctx->symbol) {
        LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_CONFIG_PARAMETER_MISSING);
        return KPEP_R_CONFIG_PARAMETER_MISSING;
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

    return KPEP_R_SUCCESS;
}

static const char* filename_from_pathname(EXTERNAL_CTX* ctx)
{
    char* ptr = strrchr(ctx->filepath, '/');
    if (ptr) ptr++;
    return (const char*) ptr;
}

#endif /* KPEP_DISABLE_EXTERNAL */
