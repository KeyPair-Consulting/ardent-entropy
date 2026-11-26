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
#include <stdint.h>
#include "openssl/params.h"
#include "openssl/crypto.h"
#include "openssl/safestack.h"

DEFINE_STACK_OF(char)

#include "ardent/ardent.h"
#include "ardent/ardent_names.h"
#include "ardent/ardent_seed_stub.h"
#include "seed_control.h"
#include "seed_sources.h"
#include "async_seed.h"

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
    uint32_t  req_hardware;
    uint32_t  req_all_sources;
    uint32_t  async_mode;

    // Count of seed sources in each category
    uint32_t v_count;
    uint32_t a_count;

    // Seed Source lists
    SEED_STUB valid[SEED_COUNT_MAX+1];  // +1 so there is always a tombstone for ptr-based access
    SEED_STUB addl [SEED_COUNT_MAX+1];  // +1 so there is always a tombstone for ptr-based access
};

static ARDENT_RESULT load_params(void* prov_ctx, SEED_CONTROL_CTX *ctx);

/* ************************************************************************************************
 * ***********************************************************************************************
 * Definitions, declarations, and context structure
 * ***********************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
void seed_control_free(SEED_CONTROL_CTX *ctx)
{
    uint32_t i;

    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }

    if (!ctx)
        return;

    // Free contexts
    for (i = 0; i < ctx->v_count; ++i) {
        if (ctx->valid[i].seed_ctx) {
            async_seed_free(ctx->valid[i].seed_ctx);
            ctx->valid[i].seed_ctx = NULL;
        }
    }
    for (i = 0; i < ctx->a_count; ++i) {
        if (ctx->addl[i].seed_ctx) {
            async_seed_free(ctx->addl[i].seed_ctx);
            ctx->addl[i].seed_ctx = NULL;
        }
    }
    ardent_cleanse(ctx, sizeof(SEED_CONTROL_CTX));
}

EXPORT_VISIBILITY_HIDDEN
SEED_CONTROL_CTX* seed_control_new(void* prov_ctx, ARDENT_RESULT *errnum)
{
    ARDENT_RESULT rv = ARDENT_R_SUCCESS;
    SEED_CONTROL_CTX *ctx = NULL;
    uint32_t i;

    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }

    // Allocate for source context
    ctx = ardent_zalloc(sizeof(SEED_CONTROL_CTX));
    if (!ctx) {
        rv = ARDENT_R_MALLOC_FAIL;
        LOG_ARDENT_ERROR(MODULE_NAME, rv);
        goto err;
    }

    // Pull runtime configuration from params
    rv = load_params(prov_ctx, ctx);
    if (rv) {
        goto err;
    }

    // Must have a validated source
    if (!ctx->valid[0].seed_ctx) {
        rv = ARDENT_R_CONFIG_PARAMETER_MISSING;
        LOG_SIMPLE_ERROR(MODULE_NAME, "No validated source specified; one is required");
        goto err;
    }

    // If restrictive mode, check for a hardware source
    if (ctx->req_hardware) {
        uint32_t found;
        for (found=0, i=0; i < ctx->v_count; ++i)
            found |= ctx->valid[i].hardware_source;
        if (!found) {
            rv = ARDENT_R_CONFIG_PARAMETER_MISSING;
            LOG_SIMPLE_ERROR(MODULE_NAME, "No hardware source specified with 'restrictive entropy counting' enabled; one is required");
            goto err;
        }
    }

    // Loop through all sources and start their threads
    if (ctx->async_mode) {
        for (i = 0; i < ctx->v_count; ++i) {
            if (ctx->valid[i].seed_ctx) {
                ARDENT_RESULT rv = async_seed_start_thread(ctx->valid[i].seed_ctx);
                if (rv) {
                    LOG_SIMPLE_ERROR(MODULE_NAME, "Failed to start thread for validated source");
                    goto err;
                }
            }
        }
        for (i = 0; i < ctx->a_count; ++i) {
            if (ctx->addl[i].seed_ctx) {
                ARDENT_RESULT rv = async_seed_start_thread(ctx->addl[i].seed_ctx);
                if (rv) {
                    LOG_SIMPLE_ERROR(MODULE_NAME, "Failed to start thread for additional source");
                    goto err;
                }
            }
        }
    }

    // Success!
    ctx->initialized = 1;
    if (errnum) *errnum = ARDENT_R_SUCCESS;
    return ctx;

err:
    if (!rv)
        rv = (seed_control_get_state(ctx) == ARDENT_RAND_STATE_ERROR  ? ARDENT_R_SEED_IN_ERROR_STATE
                                                                    : ARDENT_R_SEED_NOT_INSTANTIATED);
    seed_control_free(ctx);
    if (errnum) *errnum = rv;
    return NULL;
}

EXPORT_VISIBILITY_HIDDEN
uint32_t seed_control_get_state(SEED_CONTROL_CTX* ctx)
{
    SEED_STUB *seed = NULL;

    if (!ctx || !ctx->initialized) 
        return ARDENT_RAND_STATE_UNINITIALISED; // Value 0

    // Need to have at least one Validated source (also must be hardware if restrictive mode)
    seed = ctx->valid;
    while (seed->seed_ctx) {    
        if ((!ctx->req_hardware || seed->hardware_source) && 
            async_seed_get_state(seed->seed_ctx) == ARDENT_RAND_STATE_READY) {
            return ARDENT_RAND_STATE_READY;
        }
        seed++;
    }
    return ARDENT_RAND_STATE_ERROR;
}

EXPORT_VISIBILITY_HIDDEN
void seed_control_get_description(SEED_CONTROL_CTX* ctx, char *buffer)
{
    SEED_STUB *seed;
    STACK_OF(char) *lines;
    char *line;
    size_t used = 0;
    int idx;

    if (!ctx || !buffer)
        return;

    memset(buffer, 0, SEED_CONTROL_DESCRIPTION_MAX);
    lines = sk_char_new_null();
    if (!lines) {
        snprintf(buffer, SEED_CONTROL_DESCRIPTION_MAX,
                 "Unable to allocate source description.\n");
        return;
    }

    if (ctx->valid[0].seed_ctx) {
        seed = ctx->valid;
        while (seed->seed_ctx) {
            char namebuf[SEED_CONTROL_DESCRIPTION_MAX];
            const char *name = async_seed_get_name(seed->seed_ctx);
            if (!name) name = "(Unknown)";  // Should never happen
            if (ctx->req_hardware && seed->hardware_source)
                snprintf(namebuf, sizeof(namebuf), "%s [H]", name ? name : "");
            else
                snprintf(namebuf, sizeof(namebuf), "%s", name ? name : "");

            line = OPENSSL_strdup(namebuf);
            if (line && sk_char_push(lines, line) <= 0) {
                OPENSSL_free(line);
            }
            seed++;
        }

        seed = ctx->addl;
        if (seed->seed_ctx) {
            while (seed->seed_ctx) {
                const char *name = async_seed_get_name(seed->seed_ctx);
                line = OPENSSL_strdup(name ? name : "");
                if (line && sk_char_push(lines, line) <= 0) {
                    OPENSSL_free(line);
                }
                seed++;
            }
        }

        line = OPENSSL_strdup("[...] indicates a validated source");
        if (line && sk_char_push(lines, line) <= 0) {
            OPENSSL_free(line);
        }
        if (ctx->req_hardware) {
            line = OPENSSL_strdup("[H] indicates a hardware source");
            if (line && sk_char_push(lines, line) <= 0) {
                OPENSSL_free(line);
            }
        }
    }
    else {
        line = OPENSSL_strdup("No validated sources detected.");
        if (line && sk_char_push(lines, line) <= 0) {
            OPENSSL_free(line);
        }
    }

    for (idx = 0; idx < sk_char_num(lines); idx++) {
        line = sk_char_value(lines, idx);
        if (!line)
            continue;

        used += snprintf(buffer + used,
                         used < SEED_CONTROL_DESCRIPTION_MAX
                             ? SEED_CONTROL_DESCRIPTION_MAX - used
                             : 0,
                         "%s\n", line);

        if (used >= SEED_CONTROL_DESCRIPTION_MAX) {
            used = SEED_CONTROL_DESCRIPTION_MAX - 1;
            buffer[used] = '\0';
            break;
        }
    }

    for (idx = 0; idx < sk_char_num(lines); idx++) {
        line = sk_char_value(lines, idx);
        OPENSSL_free(line);
    }
    sk_char_free(lines);
}

EXPORT_VISIBILITY_HIDDEN
int seed_control_get_restricted_mode(SEED_CONTROL_CTX* ctx)
{
    return ctx?ctx->req_hardware:0;
}

EXPORT_VISIBILITY_HIDDEN
ARDENT_RESULT seed_control_gather(SEED_CONTROL_CTX *ctx, 
                                unsigned char **out, size_t *out_len, 
                                size_t nbits, int validated)
{
    ARDENT_RESULT    rv = ARDENT_R_SUCCESS;
    SEED_STUB     *source = NULL;
    unsigned char *buffer = NULL;
    size_t         buf_len[SEED_COUNT_MAX] = { 0 };
    size_t         buf_total = 0, accum = 0;
    uint32_t       idx = 0;
    uint32_t       hardware = 0;

//    uint32_t       gather_state[SEED_COUNT_MAX] = { 0 };
    uint32_t       successful = 0;

    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }

    if (!ctx || !out || *out || !out_len) {
        return ARDENT_R_INVALID_ARG;
    }

    // Non-validated (additional input) is optional
    if (!validated && !ctx->addl[0].seed_ctx) {
        *out_len = 0;
        *out = NULL;
        return ARDENT_R_SUCCESS;
    }

    // Get total size
    source = (validated)?ctx->valid:ctx->addl;
    while (source->seed_ctx) {
        rv = async_seed_gather(source->seed_ctx, NULL, &buf_len[idx], nbits);
        if (!rv) {
            successful++;
            if (buf_len[idx] > SIZE_MAX - buf_total) {
                rv = ARDENT_R_INVALID_ARG;
                goto err;
            }
            buf_total += buf_len[idx];
            // gather_state[idx]++;
        }
        idx++;
        source++;
    }

    // Check seed sources
    if (validated) {
        if (ctx->req_all_sources && successful != ctx->v_count) {
            rv = ARDENT_R_SEED_INSUFFICIENT_ENTROPY;
            goto err;
        }
    }
    else if (successful == 0) {
        *out_len = 0;
        *out = NULL;
        return ARDENT_R_SUCCESS;
    }

    // Each source was asked for nbits, and added at least that to buf_total on success.
    // So if true, then at least one responded with available entropy
    if (buf_total < (nbits>>3)) {
        if (!validated) {
            *out_len = 0;
            *out = NULL;
            return ARDENT_R_SUCCESS;
        }
        LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_SEED_INSUFFICIENT_ENTROPY);
        rv = ARDENT_R_SEED_INSUFFICIENT_ENTROPY;
        goto err;
    }

    // Allocate
    buffer = ardent_zalloc(buf_total);
    if (!buffer) {
        if (!validated) {
            *out_len = 0;
            *out = NULL;
            return ARDENT_R_SUCCESS;
        }
        LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_MALLOC_FAIL);
        rv = ARDENT_R_MALLOC_FAIL;
        goto err;
    }

    // Gather from each
    idx = 0;
    successful = 0;
    source = (validated)?ctx->valid:ctx->addl;
    while (source->seed_ctx) {
        rv = async_seed_gather(source->seed_ctx, buffer+accum, &buf_len[idx], nbits);
        if (!rv) {
            if (buf_len[idx] > SIZE_MAX - accum) {
                rv = ARDENT_R_INVALID_ARG;
                goto err;
            }
            successful++;
            accum += buf_len[idx];
            if (validated && ctx->req_hardware && source->hardware_source)
                hardware = 1;
        }
        idx++;
        source++;
    }

    if (validated && ctx->req_all_sources &&
        successful != ctx->v_count) {
        rv = ARDENT_R_SEED_INSUFFICIENT_ENTROPY;
        goto err;
    }

    if (!validated) {
        if (accum == 0) {
            ardent_cleanse(buffer, buf_total);
            *out_len = 0;
            *out = NULL;
            return ARDENT_R_SUCCESS;
        }
        *out = buffer;
        *out_len = accum;
        return ARDENT_R_SUCCESS;
    }

    // Check seed source counting method #1 requirements for at least one (1) hardware source
    if (ctx->req_hardware && validated && !hardware) {
        rv = ARDENT_R_SEED_CONTROL_FATAL;
        LOG_ARDENT_ERROR(MODULE_NAME, rv);
        goto err;    
    }

    // Did we gather sufficient entropy?
    // Each source provides the full nbits requested or returns error, and accum is only 
    // incremented on success.  So accum is set to the amount of bits gathered from one 
    // or more (N) sources, and contains (N * nbits) of qualified entropy, although the
    // actual number of bits may be very large if using low entropy sources.
    if (accum < (nbits>>3)) {
        rv = ARDENT_R_SEED_CONTROL_FATAL;
        LOG_ARDENT_ERROR(MODULE_NAME, rv);
        goto err;
    }

    // Success
    *out = buffer;
    *out_len = accum;
    return ARDENT_R_SUCCESS;

err:
    ardent_cleanse(buffer, buf_total);
    *out = NULL;
    *out_len = 0;
    return rv;
}

/* ***********************************************************************************************
 * ***********************************************************************************************
 * Parameters from 'ardentmodule.cnf'
 * ***********************************************************************************************
 * ***********************************************************************************************/

#define LOOKUP_KEY_LENGTH 64

static ARDENT_RESULT load_params(void* prov_ctx, SEED_CONTROL_CTX *ctx)
{
    ARDENT_RESULT rv = ARDENT_R_SUCCESS;
    OSSL_PARAM  params[5], *p = params;
    SEED_STUB  *seed = NULL;
    uint32_t   *seed_cnt = NULL;
    void       *handle = NULL;
    int32_t     ring_sz;
    char        key_start[LOOKUP_KEY_LENGTH/2];
    char        act_key[LOOKUP_KEY_LENGTH];
    char        val_key[LOOKUP_KEY_LENGTH];
    char        hard_key[LOOKUP_KEY_LENGTH];
    char        ring_key[LOOKUP_KEY_LENGTH];
    const char *act_value = NULL;
    const char *val_value = NULL;
    const char *hard_value = NULL;
    const char *ring_value = NULL;
    const SEED_SOURCE_DEF *def = NULL;

    if (!prov_ctx) {
        return ARDENT_R_NULL_ARG;
    }
    if (!ctx) {
        return ARDENT_R_NULL_ARG;
    }

    // Get additional configuration parameters
    ctx->req_all_sources =
        ardent_get_core_param_bool(prov_ctx, ARDENT_PROV_PARAM_REQ_ALL_SOURCES, 0); 
    ctx->req_hardware =
        ardent_get_core_param_bool(prov_ctx, ARDENT_PROV_PARAM_REQ_HARDWARE_SOURCE, 0);
    ctx->async_mode = 
        ardent_get_core_param_bool(prov_ctx, ARDENT_PROV_PARAM_SEED_ASYNC_MODE, 0);
    if (ctx->async_mode)
        ardent_log(LOG_LVL_INFO, MODULE_NAME, "ARDENT starting in asynchronous mode (gather from worker threads through ringbuffers)");
    else
        ardent_log(LOG_LVL_INFO, MODULE_NAME, "ARDENT starting in synchronous mode (block while gathering entropy)");

    // Initialize each seed source
    for (def = seed_source_defs; def->desc; ++def) {
        act_value = NULL;
        val_value = NULL;
        hard_value = NULL;
        ring_value = NULL;
        p = params;

        if (def->idx > 0)
            sprintf(key_start, "%s.%u", def->prefix, def->idx);
        else
            sprintf(key_start, "%s", def->prefix);

        sprintf(act_key, "%s.%s", key_start, ARDENT_PROV_PARAM_SEED_ACTIVATE);
        *p++ = OSSL_PARAM_construct_utf8_ptr(act_key, (char **) &act_value, sizeof(act_value));
        sprintf(val_key, "%s.%s", key_start, ARDENT_PROV_PARAM_SEED_VALIDATED);
        *p++ = OSSL_PARAM_construct_utf8_ptr(val_key, (char **) &val_value, sizeof(val_value));
        sprintf(hard_key, "%s.%s", key_start, ARDENT_PROV_PARAM_SEED_HARDWARE);
        *p++ = OSSL_PARAM_construct_utf8_ptr(hard_key, (char **) &hard_value, sizeof(hard_value));
        sprintf(ring_key, "%s.%s",key_start, ARDENT_PROV_PARAM_SEED_RING_SIZE);
        *p++ = OSSL_PARAM_construct_utf8_ptr(ring_key, (char **) &ring_value, sizeof(ring_value));
        *p = OSSL_PARAM_construct_end();

        if (!ardent_get_core_params(prov_ctx, params)) {
            LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_CONFIG_LOOKUP_FAILURE);
            return ARDENT_R_CONFIG_LOOKUP_FAILURE;
        }

        if (!act_value || strncmp(act_value, "1", 1)) {
            continue;
        }

        if (val_value && strncmp(val_value, "0", 1)) {
            if (!strncmp(val_value, "1", 1)) {
                ardent_log(LOG_LVL_INFO, MODULE_NAME,
                         "Seed source '%s' marked validated '1', should be identifier",
                         def->desc);
            }
            seed_cnt = &ctx->v_count;
            if (*seed_cnt >= SEED_COUNT_MAX) {
                LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_NO_SLOTS);
                return ARDENT_R_NO_SLOTS;
            }
            seed = &ctx->valid[*seed_cnt];
            if (def->force_hardware || (hard_value && !strncmp(hard_value, "1", 1))) {
                seed->hardware_source = 1;
            }
        }
        else {
            seed_cnt = &ctx->a_count;
            if (*seed_cnt >= SEED_COUNT_MAX) {
                LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_NO_SLOTS);
                return ARDENT_R_NO_SLOTS;
            }
            seed = &ctx->addl[*seed_cnt];
        }

        if (ring_value) {
            ring_sz = strtol(ring_value, NULL, 10);
            if (ring_sz <= 0 || ring_sz > INT32_MAX) {
                LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_RING_INVALID_SIZE);
                return ARDENT_R_RING_INVALID_SIZE;
            }
            if ((ring_sz & (ring_sz - 1)) != 0) {
                LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_RING_NOT_POWER_OF_TWO);
                return ARDENT_R_RING_NOT_POWER_OF_TWO;
            }
        }
        else {
            ring_sz = 1024;
        }

        handle = async_seed_new(prov_ctx,
                                def->stub_fn,
                                (uint32_t) ring_sz,
                                (uint8_t) def->idx,
                                ctx->async_mode,
                                &rv);
        if (!handle) {
            LOG_ARDENT_ERROR(MODULE_NAME, rv);
            LOG_FORMATTED_ERROR(MODULE_NAME, "Failed to initialize seed source '%s'.", def->desc);
            rv = ARDENT_R_SUCCESS;
            continue;
        }

        seed->seed_ctx = handle;
        *seed_cnt += 1;
    }

    rv = ARDENT_R_SUCCESS;
err:
    return rv;
}

