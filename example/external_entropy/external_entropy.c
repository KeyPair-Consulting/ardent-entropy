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

#include "ardent/ardent.h"
#include "ardent/ardent_names.h"
#include "ardent/ardent_seed_stub.h"

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

#define MODULE_NAME "SAMPLE-JITTER"

typedef struct {
    char     name[32];
    uint32_t state;
    uint32_t full_entropy;
    double   entropy_per_bit;
    size_t   block_size;
    size_t   block_count;

    // Source-specific parameters
    unsigned int osr; 
} JITTER_CTX;

/* ***********************************************************************************************
* ***********************************************************************************************
* Stub functions
* ***********************************************************************************************
* ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
void stub_example_free(void *ctx)
{
    if (ardent_trace_seed_enabled) {
        printf("*** %s: %s\n", MODULE_NAME, __func__);
    }

    ardent_cleanse(ctx, sizeof(JITTER_CTX));
    ardent_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'sample-jitter' shutdown successful");
}

EXPORT_VISIBILITY_HIDDEN
void* stub_example_new(void* prov_ctx, uint8_t idx, ARDENT_RESULT *errnum)
{
    JITTER_CTX *ctx;
    size_t full_entropy_sz;
    int ret;

    if (ardent_trace_seed_enabled) {
        printf("*** %s: %s\n", MODULE_NAME, __func__);
    }

#ifdef FIPS_OPTEST
    {
        const char* debug = getenv(ENV_OPTEST_SEED_JITTER_NEW);
        if (debug) {
            LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'sample-jitter' failed startup (optest)");
            if (errnum) *errnum = ARDENT_R_FIPS_OPTEST;
            return NULL;
        }
    }
#endif

    // Allocate for source context
    ctx = ardent_zalloc(sizeof(JITTER_CTX));
    if (ctx == NULL) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'sample-jitter' failed startup (malloc)");
        if (errnum) *errnum = ARDENT_R_MALLOC_FAIL;
        return NULL;
    }

    // Set runtime configuration
    strcpy(ctx->name, "ARDent JEnt example");
    ctx->block_size = 256;
    ctx->block_count = 1;
    ctx->osr = 4;  // Set by E239

    // Set entropy factors
    full_entropy_sz = ctx->block_size * ctx->block_count;
    if (full_entropy_sz < ARDENT_SECURITY_STRENGTH_BITS) {
        LOG_SIMPLE_ERROR(MODULE_NAME, "Seed source 'sample-jitter' failed startup (block size check)");
        ardent_cleanse(ctx, sizeof(JITTER_CTX));
        if (errnum) *errnum = ARDENT_R_INVALID_ARG;
        return NULL;        
    }
    ctx->full_entropy = (ARDENT_SECURITY_STRENGTH_BITS == full_entropy_sz);
    if (!ctx->full_entropy)
        ctx->entropy_per_bit = (double) ARDENT_SECURITY_STRENGTH_BITS / (double) full_entropy_sz;

    // Initialize source
    if ((ret = jent_entropy_init_ex(ctx->osr, JENT_ARDENT_FLAGS)) != 0) {
        LOG_FORMATTED_ERROR(MODULE_NAME, "Seed source 'sample-jitter' failed startup (library); errnum (%d)", ret);
        ardent_cleanse(ctx, sizeof(JITTER_CTX));
        if (errnum) *errnum = ARDENT_R_SEED_NOT_INSTANTIATED;
        return NULL;
    }

    // Start initialized
    ardent_log(LOG_LVL_INFO, MODULE_NAME, "Seed source 'sample-jitter' startup successful");
    ctx->state = ARDENT_RAND_STATE_READY;
    return ctx;
}

EXPORT_VISIBILITY_HIDDEN
ARDENT_RESULT stub_example_gather(void *stub_ctx, unsigned char *out, size_t *out_len, size_t nbits)
{
    JITTER_CTX *ctx = (JITTER_CTX *)stub_ctx;
    ARDENT_RESULT rv = ARDENT_R_SUCCESS;
    size_t gather_sz, gather_ovf;

    struct rand_data *jitter_ec = NULL;
    ssize_t result = 0;
    size_t num_tries;

    if (ardent_trace_seed_enabled) {
        printf("*** %s: %s\n", MODULE_NAME, __func__);
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
            return ARDENT_R_SEED_FATAL_ERROR;
        }
    }
#endif

    if (!nbits)
        return ARDENT_R_SUCCESS;

    // Validate context
    if (!ctx || !out_len) {
        LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_NULL_ARG);
        return ARDENT_R_NULL_ARG;
    }

    // Calculate gather size and Quantize to block size
    gather_sz = (ctx->full_entropy)?nbits:(size_t) (nbits / ctx->entropy_per_bit);
    gather_ovf = (gather_sz % ctx->block_size);
    if (gather_ovf)
        gather_sz += (ctx->block_size - gather_ovf);
    gather_sz = gather_sz>>3;  // Bits to bytes
    
    if (ardent_trace_seed_enabled) {
        printf("*** %s: req %lu -> %lu\n", MODULE_NAME, nbits, gather_sz<<3);
    }

    // Return gather size?
    if (!out) {
        *out_len = gather_sz;
        return ARDENT_R_SUCCESS;
    }

    // Check for adequate size
    if (*out_len < gather_sz) {
        LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_SEED_BUFFER_TOO_SMALL);
        return ARDENT_R_SEED_BUFFER_TOO_SMALL;
    }

    // Check state
    if (ctx->state != ARDENT_RAND_STATE_READY) {
        LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_SEED_NOT_READY);
        return ARDENT_R_SEED_NOT_READY;
    }

    // Retry intermittent failures, then give up
    for (num_tries = 0; num_tries < JITTER_MAX_NUM_TRIES; num_tries++) {
        /* Allocate a fresh collector */
        jitter_ec = jent_entropy_collector_alloc(ctx->osr, JENT_ARDENT_FLAGS);
        if (jitter_ec == NULL)
            continue;

        /* Do not use _safe API as per typical security policies */
        result = jent_read_entropy(jitter_ec, (char *) out, gather_sz);
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
        if (result >= 0 && (size_t)result == gather_sz)  {
            *out_len = gather_sz;
            return ARDENT_R_SUCCESS;
        }
    }

    // If no error already set, assume a general error
    if (!rv)
        rv = ARDENT_R_ERROR_RETRIEVING_ENTROPY;

    // Zeroize
    ardent_cleanse(out, *out_len);
    *out_len = 0;

    // Permanent failure or too many intermittent failures
    ctx->state = ARDENT_RAND_STATE_ERROR;
    return rv;
}

EXPORT_VISIBILITY_HIDDEN
uint32_t stub_example_get_state(void* stub_ctx)
{
    JITTER_CTX *ctx = (JITTER_CTX *)stub_ctx;
    if (!ctx) 
        return ARDENT_RAND_STATE_UNINITIALISED; // Value 0
    return ctx->state;
}

EXPORT_VISIBILITY_HIDDEN
const char* stub_example_get_name(void* stub_ctx) 
{
    JITTER_CTX *ctx = (JITTER_CTX *)stub_ctx;
    if (!ctx) {
        ardent_log(LOG_LVL_WARN, MODULE_NAME, "get_name(sample-jitter) called with NULL context (should not happen)");
        return NULL;
    }   
    return (const char*) ctx->name;
}

/* ***********************************************************************************************
* ***********************************************************************************************
* Stub function list
* ***********************************************************************************************
* ***********************************************************************************************/

const STUB_FUNCTIONS stub_example = {
    .new_fn = stub_example_new,
    .free_fn = stub_example_free,
    .gather_fn = stub_example_gather,
    .get_name_fn = stub_example_get_name,
    .get_state_fn = stub_example_get_state,
};
