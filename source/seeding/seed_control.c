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

#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "openssl/params.h"

#include "kpep/kpep.h"
#include "kpep/kpep_names.h"
#include "kpep/kpep_seed_stub.h"
#include "seed_control.h"
#include "seed_sources.h"
#include "async_ringbuffer.h"

/* ************************************************************************************************
 * ***********************************************************************************************
 * Definitions, declarations, and context structure
 * ***********************************************************************************************
 * ***********************************************************************************************/

#define MODULE_NAME "SEED-CTRL"

// Data struct for stub management
typedef struct {
    ASYNC_CTX  *seed_ctx;
    uint32_t    hardware_source;
} SEED_STUB;

#define SEED_COUNT_MAX 8

// Control Context
struct seed_control_ctx_st {
    uint32_t  initialized;
    uint32_t  restricted_counting;

    // Count of seed sources in each category
    uint32_t v_count;
    uint32_t a_count;

    // Seed Source lists
    SEED_STUB valid[SEED_COUNT_MAX+1];  // +1 so there is always a tombstone for ptr-based access
    SEED_STUB addl [SEED_COUNT_MAX+1];  // +1 so there is always a tombstone for ptr-based access
};

static KPEP_RESULT load_params(void* prov_ctx, SEED_CONTROL_CTX *ctx);

/* ************************************************************************************************
 * ***********************************************************************************************
 * Definitions, declarations, and context structure
 * ***********************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
void seed_control_free(SEED_CONTROL_CTX *ctx)
{
    SEED_STUB *seed = NULL;

    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif

    if (!ctx)
        return;

    seed = ctx->valid;
    while (seed->seed_ctx) {
        async_ringbuffer_free(seed->seed_ctx);
        seed->seed_ctx = NULL;
        seed++;
    }
    seed = ctx->addl;
    while (seed->seed_ctx) {
        async_ringbuffer_free(seed->seed_ctx);
        seed->seed_ctx = NULL;
        seed++;
    }
    kpep_cleanse(ctx, sizeof(SEED_CONTROL_CTX));
}

EXPORT_VISIBILITY_HIDDEN
SEED_CONTROL_CTX* seed_control_new(void* prov_ctx, KPEP_RESULT *errnum)
{
    KPEP_RESULT rv = KPEP_R_SUCCESS;
    SEED_CONTROL_CTX *ctx = NULL;

    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif

    // Allocate for source context
    ctx = kpep_zalloc(sizeof(SEED_CONTROL_CTX));
    if (!ctx) {
        rv = KPEP_R_MALLOC_FAIL;
        LOG_KPEP_ERROR(MODULE_NAME, rv);
        goto err;
    }

    // Pull runtime configuration from params
    rv = load_params(prov_ctx, ctx);
    if (rv) {
        goto err;
    }

    // Must have a validated source
    if (!ctx->valid[0].seed_ctx) {
        rv = KPEP_R_CONFIG_PARAMETER_MISSING;
        LOG_SIMPLE_ERROR(MODULE_NAME, "No validated source specified; one is required");
        goto err;
    }

    // If restrictive mode, check for a hardware source
    if (ctx->restricted_counting) {
        uint32_t i, found;
        for (found=0, i=0; i < ctx->v_count; ++i)
            found |= ctx->valid[i].hardware_source;
        if (!found) {
            rv = KPEP_R_CONFIG_PARAMETER_MISSING;
            LOG_SIMPLE_ERROR(MODULE_NAME, "No hardware source specified with 'restrictive entropy counting' enabled; one is required");
            goto err;
        }
    }

    // Success!
    ctx->initialized = 1;
    if (errnum) *errnum = KPEP_R_SUCCESS;
    return ctx;

err:
    if (!rv)
        rv = (seed_control_get_state(ctx) == KPEP_RAND_STATE_ERROR  ? KPEP_R_SEED_IN_ERROR_STATE
                                                                    : KPEP_R_SEED_NOT_INSTANTIATED);
    seed_control_free(ctx);
    if (errnum) *errnum = rv;
    return NULL;
}

EXPORT_VISIBILITY_HIDDEN
uint32_t seed_control_get_state(SEED_CONTROL_CTX* ctx)
{
    SEED_STUB *seed = NULL;

    if (!ctx || !ctx->initialized) 
        return KPEP_RAND_STATE_UNINITIALISED; // Value 0

    // Need to have at least one Validated source (also must be hardware if restrictive mode)
    seed = ctx->valid;
    while (seed->seed_ctx) {    
        if ((!ctx->restricted_counting || seed->hardware_source) && 
            async_ringbuffer_get_state(seed->seed_ctx) == KPEP_RAND_STATE_READY) {
            return KPEP_RAND_STATE_READY;
        }
        seed++;
    }
    return KPEP_RAND_STATE_ERROR;
}

EXPORT_VISIBILITY_HIDDEN
void seed_control_get_description(SEED_CONTROL_CTX* ctx, char *buffer)
{
    SEED_STUB *seed;

    if (ctx && buffer) {
        memset(buffer, 0, SEED_CONTROL_DESCRIPTION_MAX);

        // Validated sources
        if (ctx->valid[0].seed_ctx) {
            seed = ctx->valid;
            while (seed->seed_ctx) {
                sprintf(buffer+strlen(buffer), "%s%s\n", async_ringbuffer_get_name(seed->seed_ctx),
                (ctx->restricted_counting && seed->hardware_source)?" [H]":"");
                seed++;
            }
        }
        else {
            sprintf(buffer, "No validated sources detected.\n");
            return;
        }

        // Additional sources
        if (ctx->addl[0].seed_ctx) {
            seed = ctx->addl;
            while (seed->seed_ctx) {
                sprintf(buffer+strlen(buffer), "%s\n", async_ringbuffer_get_name(seed->seed_ctx));
                seed++;
            }
        }
        sprintf(buffer+strlen(buffer), "%s%s\n", "[...] indicates a validated source",
                        ctx->restricted_counting?"\n[H] indicates a hardware source":"");
    }
}

EXPORT_VISIBILITY_HIDDEN
int seed_control_get_restricted_mode(SEED_CONTROL_CTX* ctx)
{
    return ctx?ctx->restricted_counting:0;
}

EXPORT_VISIBILITY_HIDDEN
KPEP_RESULT seed_control_gather(SEED_CONTROL_CTX *ctx, 
                                unsigned char **out, size_t *out_len, 
                                size_t nbits, int validated)
{
    KPEP_RESULT    rv;
    SEED_STUB     *seed = NULL;
    unsigned char *buffer = NULL;
    size_t         buf_len[SEED_COUNT_MAX] = { 0 };
    size_t         buf_total = 0, accum = 0;
    uint32_t       idx = 0;
    uint32_t       hardware = 0;

    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif

    // Validate
    if (!ctx || !out) {
        return KPEP_R_NULL_ARG;
    }
    if (!out_len) {
        return KPEP_R_INVALID_ARG;
    }
    if (!validated && !ctx->addl[0].seed_ctx) {
        *out_len = 0;
        *out = NULL;
        return KPEP_R_SUCCESS;
    }

    // Get total size
    seed = (validated)?ctx->valid:ctx->addl;
    while (seed->seed_ctx) {
        rv = async_ringbuffer_gather(seed->seed_ctx, NULL, &buf_len[idx], nbits);
        if (!rv)
            buf_total += buf_len[idx];
        idx++;
        seed++;
    }
    if (buf_total < nbits>>3) {
        rv = KPEP_R_SEED_FATAL_ERROR;
        LOG_KPEP_ERROR(MODULE_NAME, rv);
        goto err;
    }

    // Allocate
    buffer = kpep_zalloc(buf_total);
    if (!buffer) {
        rv = KPEP_R_MALLOC_FAIL;
        LOG_KPEP_ERROR(MODULE_NAME, rv);
        goto err;
    }

    // Gather from each
    idx = 0;
    seed = (validated)?ctx->valid:ctx->addl;
    while (seed->seed_ctx) {
        rv = async_ringbuffer_gather(seed->seed_ctx, buffer+accum, &buf_len[idx], nbits);
        if (!rv) {
            accum += buf_len[idx];
            if (ctx->restricted_counting && validated && seed->hardware_source)
                hardware = 1;
        }
        idx++;
        seed++;
    }

    // Check seed source counting method #1 requirements for at least one (1) hardware source
    if (ctx->restricted_counting && validated && !hardware) {
        rv = KPEP_R_SEED_FATAL_ERROR;
        LOG_KPEP_ERROR(MODULE_NAME, rv);
        goto err;    
    }

    // Did we gather sufficient entropy?
    // Each source provides the full nbits requested or returns error, and accum is only 
    // incremented on success.  So accum is set to the amount of bits gathered from one 
    // or more (N) sources, and contains (N * nbits) of qualified entropy, although the
    // actual number of bits may be very large if using low entropy sources.
    if (accum < nbits>>3) {
        rv = KPEP_R_SEED_FATAL_ERROR;
        LOG_KPEP_ERROR(MODULE_NAME, rv);
        goto err;
    }

    // Success
    *out = buffer;
    *out_len = buf_total;
    return KPEP_R_SUCCESS;
err:
    kpep_cleanse(buffer, buf_total);
    return rv;
}

/* ***********************************************************************************************
 * ***********************************************************************************************
 * Parameters from 'kpepmodule.cnf'
 * ***********************************************************************************************
 * ***********************************************************************************************/

#define LOOKUP_KEY_LENGTH 32

static KPEP_RESULT load_params(void* prov_ctx, SEED_CONTROL_CTX *ctx)
{
    KPEP_RESULT rv = KPEP_R_SUCCESS;
    OSSL_PARAM  params[5], *p = params;
    SEED_STUB  *seed = NULL;
    uint32_t   *seed_cnt = NULL;
    void       *handle = NULL;
    int32_t     ring_sz;
    char        act_key[LOOKUP_KEY_LENGTH];
    char        val_key[LOOKUP_KEY_LENGTH];
    char        hard_key[LOOKUP_KEY_LENGTH];
    char        ring_key[LOOKUP_KEY_LENGTH];
    const char *act_value = NULL;
    const char *val_value = NULL;
    const char *hard_value = NULL;
    const char *ring_value = NULL;
    const SEED_SOURCE_DEF *def = NULL;

    if (!ctx) {
        return KPEP_R_NULL_ARG;
    }

    // Non-provider startup keeps existing jitter-only behavior.
    if (!prov_ctx) {
        seed_cnt = &ctx->v_count;
        seed = &ctx->valid[*seed_cnt];
        handle = async_ringbuffer_new(NULL, &stub_jitter, 1024, 0, &rv);
        if (!handle || rv) {
            if (handle && stub_jitter.free_fn) {
                stub_jitter.free_fn(handle);
            }
            return rv ? rv : KPEP_R_SEED_NOT_INSTANTIATED;
        }
        seed->seed_ctx = handle;
        *seed_cnt += 1;
        return KPEP_R_SUCCESS;
    }

    ctx->restricted_counting =
        kpep_get_core_param_bool(prov_ctx, KPEP_PROV_PARAM_RESTRICTIVE_COUNTING, 0);

    for (def = seed_source_defs; def->desc; ++def) {
        act_value = NULL;
        val_value = NULL;
        hard_value = NULL;
        ring_value = NULL;
        p = params;

        if (def->idx > 0)
            sprintf(act_key, "%s.%u.%s", def->prefix, def->idx, KPEP_PROV_PARAM_SEED_ACTIVATE);
        else
            sprintf(act_key, "%s.%s", def->prefix, KPEP_PROV_PARAM_SEED_ACTIVATE);
        *p++ = OSSL_PARAM_construct_utf8_ptr(act_key, (char **) &act_value, sizeof(act_value));

        if (def->idx > 0)
            sprintf(val_key, "%s.%u.%s", def->prefix, def->idx, KPEP_PROV_PARAM_SEED_VALIDATED);
        else
            sprintf(val_key, "%s.%s", def->prefix, KPEP_PROV_PARAM_SEED_VALIDATED);
        *p++ = OSSL_PARAM_construct_utf8_ptr(val_key, (char **) &val_value, sizeof(val_value));

        if (def->idx > 0)
            sprintf(hard_key, "%s.%u.%s", def->prefix, def->idx, KPEP_PROV_PARAM_SEED_HARDWARE);
        else
            sprintf(hard_key, "%s.%s", def->prefix, KPEP_PROV_PARAM_SEED_HARDWARE);
        *p++ = OSSL_PARAM_construct_utf8_ptr(hard_key, (char **) &hard_value, sizeof(hard_value));

        if (def->idx > 0)
            sprintf(ring_key, "%s.%u.%s", def->prefix, def->idx, KPEP_PROV_PARAM_SEED_RING_SIZE);
        else
            sprintf(ring_key, "%s.%s", def->prefix, KPEP_PROV_PARAM_SEED_RING_SIZE);
        *p++ = OSSL_PARAM_construct_utf8_ptr(ring_key, (char **) &ring_value, sizeof(ring_value));
        *p = OSSL_PARAM_construct_end();

        if (!kpep_get_core_params(prov_ctx, params)) {
            LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_CONFIG_LOOKUP_FAILURE);
            return KPEP_R_CONFIG_LOOKUP_FAILURE;
        }

        if (!act_value || strncmp(act_value, "1", 1)) {
            continue;
        }

        if (val_value && strncmp(val_value, "0", 1)) {
            if (!strncmp(val_value, "1", 1)) {
                kpep_log(LOG_LVL_INFO, MODULE_NAME,
                         "Seed source '%s' marked validated '1', should be identifier",
                         def->desc);
            }
            seed_cnt = &ctx->v_count;
            seed = &ctx->valid[*seed_cnt];
            if (def->force_hardware || (hard_value && strncmp(hard_value, "0", 1))) {
                seed->hardware_source = 1;
            }
        }
        else {
            seed_cnt = &ctx->a_count;
            seed = &ctx->addl[*seed_cnt];
        }

        if (ring_value) {
            ring_sz = strtol(ring_value, NULL, 10);
            if (ring_sz <= 0 || ring_sz > INT32_MAX) {
                LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_RING_INVALID_SIZE);
                return KPEP_R_RING_INVALID_SIZE;
            }
        }
        else {
            ring_sz = 1024;
        }

        handle = async_ringbuffer_new(prov_ctx,
                                      def->stub_fn,
                                      (uint32_t) ring_sz,
                                      (uint8_t) def->idx,
                                      &rv);
        if (!handle) {
            LOG_FORMATTED_ERROR(MODULE_NAME, "Failed to initialize seed source '%s'.", def->desc);
            LOG_KPEP_ERROR(MODULE_NAME, rv);
            rv = KPEP_R_SUCCESS;
            continue;
        }
        if (rv) {
            LOG_FORMATTED_ERROR(MODULE_NAME, "Error initializing seed source '%s'.", def->desc);
            LOG_KPEP_ERROR(MODULE_NAME, rv);
            def->stub_fn->free_fn(handle);
            goto err;
        }

        seed->seed_ctx = handle;
        *seed_cnt += 1;
    }

    rv = KPEP_R_SUCCESS;
err:
    return rv;
}

