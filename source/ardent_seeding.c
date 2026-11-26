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

#include "openssl/err.h"
#include "openssl/rand.h"
#include "openssl/crypto.h"
#include "openssl/core_names.h"

#include "openssl/proverr.h"
#include "openssl/self_test.h"
#include "openssl/prov/providercommon.h"
#include "internal/thread_arch.h"

#if defined(OPENSSL_THREADS_NONE)
#error "ARDENT requires OpenSSL thread support; OPENSSL_THREADS_NONE is unsupported"
#endif

#include "ardent/ardent_names.h"
#include "ardent/ardent_seed_stub.h"
#include "seeding/seed_control.h"
#include "crypto/drbg.h"
#include "ardent_internal.h"

#define MODULE_NAME "ARDENT-SEED"

struct ardent_seeding_ctx_st {
    SEED_CONTROL_CTX *ctrl_ctx;
    ARDENT_DRBG_CTX    *drbg_ctx;
    const char       *perso_string;
    RBG_ENTROPY_MODE  rbg_entropy_mode;
    int               drbg_instantiated;
    CRYPTO_MUTEX     *lock;
    char             seed_description[SEED_CONTROL_DESCRIPTION_MAX];
};

typedef struct {
    ARDENT_SEEDING_CTX *service;
    int               instantiated;
} ARDENT_RAND_CTX;

// RETAINED FOR COMMENTS DURING REFACTORING -- DELETE BEFORE RELEASE
// Flag to denote DRBG instantiation (delayed until first use, in one of two places)
//static uint32_t          drbg_instantiated = 0;

// Static buffer for description to be assembled
//static char seed_description[SEED_CONTROL_DESCRIPTION_MAX] = { 0 };

#define RAISE_ERROR(rv) \
    if ((rv) == ARDENT_R_SEED_CONTROL_FATAL) { \
        ossl_set_error_state(OSSL_SELF_TEST_TYPE_CRNG); \
        ERR_raise(ERR_LIB_PROV, PROV_R_ENTROPY_SOURCE_FAILED_CONTINUOUS_TESTS); \
    } \
    else { ERR_raise(ERR_LIB_ARDENT, rv); }

/* ***********************************************************************************************
 * ***********************************************************************************************
 *  Seeding Context and Service
 * ***********************************************************************************************
 * ***********************************************************************************************/

static ARDENT_RESULT load_params(void* prov_ctx, ARDENT_SEEDING_CTX *ctx);

EXPORT_VISIBILITY_HIDDEN
void ardent_seeding_free(ARDENT_SEEDING_CTX *ctx)
{
    if (!ctx)
        return;

    if (ctx->lock)
        ossl_crypto_mutex_lock(ctx->lock);
    if (ctx->drbg_ctx) {
        drbg_uninstantiate(ctx->drbg_ctx);
        drbg_free(ctx->drbg_ctx);
        ctx->drbg_ctx = NULL;
    }
    if (ctx->ctrl_ctx) {
        seed_control_free(ctx->ctrl_ctx);
        ctx->ctrl_ctx = NULL;
    }
    if (ctx->lock) {
        ossl_crypto_mutex_unlock(ctx->lock);
        ossl_crypto_mutex_free(&ctx->lock);
    }
    ardent_cleanse(ctx, sizeof(*ctx));
}

EXPORT_VISIBILITY_HIDDEN
ARDENT_SEEDING_CTX* ardent_seeding_new(void* prov_ctx)
{
    ARDENT_RESULT rv;
    ARDENT_SEEDING_CTX *ctx = NULL;

    if (!prov_ctx) {
        LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_NULL_ARG);
        return NULL;
	}

    if (ardent_trace_seed_enabled) {
        ardent_trace(MODULE_NAME, "Seed subsystem Init Start");
    }

    ctx = ardent_zalloc(sizeof(*ctx));
    if (!ctx) {
        LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_MALLOC_FAIL);
        return NULL;
	}
    ctx->rbg_entropy_mode = ENTROPY_MODE_RBG3;
    ctx->lock = ossl_crypto_mutex_new();
    if (!ctx->lock) {
        LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_MUTEX_FAIL_START);
        ardent_cleanse(ctx, sizeof(*ctx));
        return NULL;
    }

    ossl_crypto_mutex_lock(ctx->lock);
    rv = load_params(prov_ctx, ctx);
    if (rv == ARDENT_R_SUCCESS)
        ctx->ctrl_ctx = seed_control_new(prov_ctx, &rv);
    if (rv == ARDENT_R_SUCCESS && ctx->ctrl_ctx)
        ctx->drbg_ctx = drbg_new(ctx->ctrl_ctx, ctx->rbg_entropy_mode, &rv);
    if (rv == ARDENT_R_SUCCESS && (!ctx->ctrl_ctx || !ctx->drbg_ctx))
        rv = ARDENT_R_SEED_NOT_INSTANTIATED;
    if (rv == ARDENT_R_SUCCESS)
        seed_control_get_description(ctx->ctrl_ctx, ctx->seed_description);
    ossl_crypto_mutex_unlock(ctx->lock);

    if (rv != ARDENT_R_SUCCESS) {
        LOG_ARDENT_ERROR(MODULE_NAME, rv);
        ardent_seeding_free(ctx);
        RAISE_ERROR(rv);
        return NULL;
    }

    if (ardent_trace_seed_enabled) {
        ardent_trace(MODULE_NAME, "Seed subsystem Init Complete");
    }

    return ctx;
}

EXPORT_VISIBILITY_HIDDEN
const char* ardent_seeding_get_description(ARDENT_SEEDING_CTX *ctx)
{
    return ctx ? ctx->seed_description : "";
}

EXPORT_VISIBILITY_HIDDEN
int ardent_seeding_get_restricted_mode(ARDENT_SEEDING_CTX *ctx)
{
    int result;

    if (!ctx || !ctx->lock)
        return 0;
    ossl_crypto_mutex_lock(ctx->lock);
    result = seed_control_get_restricted_mode(ctx->ctrl_ctx);
    ossl_crypto_mutex_unlock(ctx->lock);
    return result;
}

// Context must be locked before calling this function
static int seed_service_instantiate(ARDENT_SEEDING_CTX *service)
{
    if (service->drbg_instantiated)
        return 1;

    service->drbg_instantiated = !!(ARDENT_R_SUCCESS == 
        drbg_instantiate(service->drbg_ctx, ARDENT_SECURITY_STRENGTH_BITS,
                         (const uint8_t *)service->perso_string,
                         service->perso_string ? (uint32_t)strlen(service->perso_string):0));
    return service->drbg_instantiated;
}

// Context must be locked before calling this function
static int seed_service_verify_ready(ARDENT_SEEDING_CTX* service) 
{
    int32_t state;

    // FIPS: Ensure provider is not in error state
    if (!ossl_prov_is_running())
        return 0;

    // DRBG Instantiated?
    if (!service->drbg_instantiated && !seed_service_instantiate(service)) {
        return 0;
    }

    // Sources ready?
    state = seed_control_get_state(service->ctrl_ctx);
    if (state != ARDENT_RAND_STATE_READY) {
        RAISE_ERROR(state == ARDENT_RAND_STATE_ERROR ? PROV_R_IN_ERROR_STATE
                                                   : PROV_R_NOT_INSTANTIATED);
        return 0;
    }

    return 1;
}

/* ***********************************************************************************************
 * ***********************************************************************************************
 * OpenSSL EVP_RAND API
 * ***********************************************************************************************
 * ***********************************************************************************************/

static void ardent_rand_free(void *seed_ctx)
{
    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }
    ardent_cleanse(seed_ctx, sizeof(ARDENT_RAND_CTX));
}

static void *ardent_rand_new(void *provctx, void *parent,
                        const OSSL_DISPATCH *parent_dispatch)
{
    ARDENT_RAND_CTX *ctx;

    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }

    if (parent != NULL) {
        RAISE_ERROR(PROV_R_SEED_SOURCES_MUST_NOT_HAVE_A_PARENT);
        return NULL;
    }

    ctx = ardent_zalloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->service = ardent_provider_get_seeding(provctx);
    if (!ctx->service) {
        ardent_free(ctx);
        return NULL;
    }
    return ctx;
}

static int ardent_rand_instantiate(void *seed_ctx, unsigned int strength,
                                 ossl_unused int prediction_resistance,
                                 ossl_unused const unsigned char *pstr,
                                 ossl_unused size_t pstr_len,
                                 ossl_unused const OSSL_PARAM params[])
{
    ARDENT_RAND_CTX *ctx = (ARDENT_RAND_CTX *)seed_ctx;

    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }

    if (!ctx || !ctx->service || !ctx->service->lock ||
        strength > ARDENT_SECURITY_STRENGTH_BITS)
        return 0;

    ossl_crypto_mutex_lock(ctx->service->lock);
    ctx->instantiated = seed_service_instantiate(ctx->service);
    ossl_crypto_mutex_unlock(ctx->service->lock);
    return ctx->instantiated;
}

static int ardent_rand_uninstantiate(void *seed_ctx)
{
    ARDENT_RAND_CTX *ctx = (ARDENT_RAND_CTX *)seed_ctx;

    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }

    if (!ctx || !ctx->service || !ctx->service->lock)
        return 0;

    ossl_crypto_mutex_lock(ctx->service->lock);
    ctx->instantiated = 0;
    ossl_crypto_mutex_unlock(ctx->service->lock);
    return 1;
}

// TODO: Can we remove rand_reseed (don't declare reseed service)
static int ardent_rand_reseed(ossl_unused void *seed_ctx,
                            ossl_unused int prediction_resistance,
                            ossl_unused const unsigned char *ent,
                            ossl_unused size_t ent_len,
                            ossl_unused const unsigned char *adin,
                            ossl_unused size_t adin_len)
{
    // Ignore; Reseed is handled internally
    return 0;
    /*
    ARDENT_RAND_CTX *ctx = (ARDENT_RAND_CTX *)seed_ctx;
    uint32_t state;

    if (!ctx || !ctx->service || !ctx->service->lock)
        return 0;

    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }

    // FIPS: Ensure provider is not in error state
    if (!ossl_prov_is_running())
        return 0;

    // Ignore; Reseed is handled internally
    return 1;
    */
}

static int ardent_rand_generate(void *seed_ctx, unsigned char *out, size_t outlen,
                              unsigned int strength,
                              ossl_unused int prediction_resistance,
                              ossl_unused const unsigned char *adin,
                              ossl_unused size_t adin_len)
{
    ARDENT_RAND_CTX *ctx = (ARDENT_RAND_CTX *)seed_ctx;
    ARDENT_RESULT rv = ARDENT_R_SUCCESS;
    int ok;
    
    if (ardent_trace_seed_enabled) {
        ardent_trace_fmt(MODULE_NAME, "%s (req %lu) bits", __func__, outlen);
    }

    if (!ctx || !ctx->service || !ctx->service->lock || !out)
        return 0;
    if (outlen == 0 || outlen > DRBG_MAX_BYTES_PER_REQUEST || strength > ARDENT_SECURITY_STRENGTH_BITS)
        return 0;

    // Generate
    ossl_crypto_mutex_lock(ctx->service->lock);
    if (ctx->instantiated && seed_service_verify_ready(ctx->service)) {
        rv = drbg_generate(ctx->service->drbg_ctx, out, outlen);
        if (rv != ARDENT_R_SUCCESS) {
            // Error logged in DRBG/Seed-source
            RAISE_ERROR(rv);
            outlen = 0;
        }
    }
    else {
        outlen = 0;
    }
    ossl_crypto_mutex_unlock(ctx->service->lock);

    return (int) outlen; // Return bytes!
}

static size_t ardent_rand_get_seed(void *seed_ctx, unsigned char **pout,
                                 int entropy, size_t min_len,
                                 size_t max_len,
                                 ossl_unused int prediction_resistance,
                                 ossl_unused const unsigned char *adin,
                                 ossl_unused size_t adin_len)
{
    ARDENT_RAND_CTX *ctx = (ARDENT_RAND_CTX *)seed_ctx;

    unsigned char *buffer = NULL;
    size_t         buflen = 0, reslen;
    size_t         requested = (((size_t)entropy+7)/8); // Bytes

    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }

    if (!ctx || !ctx->service || !ctx->service->lock)
        return 0;
    if (!pout || *pout || max_len < min_len || entropy <= 0 || requested > max_len)
        return 0;

    buflen = (requested < min_len)?min_len:requested;

    if (ardent_trace_seed_enabled) {
        ardent_trace_fmt(MODULE_NAME, "request (%lu<%lu<%lu=%lu) bytes", min_len, requested, max_len, buflen);
    }

    buffer = ardent_zalloc(buflen);
    if (!buffer) {
        LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_MALLOC_FAIL);
        RAISE_ERROR(ARDENT_R_MALLOC_FAIL);
        return 0;
    }

    // Generate
    reslen = ardent_rand_generate(seed_ctx, buffer, buflen, 0, 0, NULL, 0);
    if (reslen) {
        *pout = buffer;
    }
    else {
        ardent_cleanse(buffer, buflen);
    }

    return reslen;
}
 
static void ardent_rand_clear_seed(ossl_unused void *seed_ctx,
                               unsigned char *out, size_t outlen)
{
    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }
    if (!out)
        return;
    ardent_cleanse(out, outlen);
}

static int ardent_rand_verify_zeroization(void *seed_ctx)
{
    ARDENT_RAND_CTX *ctx = (ARDENT_RAND_CTX *)seed_ctx;
    int rv;

    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }

    if (!ctx || !ctx->service || !ctx->service->lock || !ctx->service->drbg_ctx)
        return 1;

    // The Seeding DRBG doesn't uninstantiate until the provider is unloaded.
    // As a result, this call to verify_zeroization should always fail.  
    // TODO: Validate this zeroization check under OpTest scenarios.
    ossl_crypto_mutex_lock(ctx->service->lock);
    rv = drbg_verify_zeroization(ctx->service->drbg_ctx);
    ossl_crypto_mutex_unlock(ctx->service->lock);
    return rv;
}
 

static int ardent_rand_get_ctx_params(void *seed_ctx, OSSL_PARAM params[])
{
    ARDENT_RAND_CTX *ctx = (ARDENT_RAND_CTX *)seed_ctx;
    uint32_t state;
    OSSL_PARAM *p;

    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }
    if (!ctx || !ctx->service || !ctx->service->lock)
        return 0;

    ossl_crypto_mutex_lock(ctx->service->lock);
    state = ctx->instantiated ? seed_control_get_state(ctx->service->ctrl_ctx)
                              : ARDENT_RAND_STATE_UNINITIALISED;
    ossl_crypto_mutex_unlock(ctx->service->lock);

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p && !OSSL_PARAM_set_int(p, state))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p && !OSSL_PARAM_set_uint(p, ARDENT_SECURITY_STRENGTH_BITS))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p && !OSSL_PARAM_set_size_t(p, DRBG_MAX_BYTES_PER_REQUEST))
        return 0;
    return 1;
}

static const OSSL_PARAM *ardent_rand_gettable_ctx_params(ossl_unused void *seed_ctx,
                                                       ossl_unused void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END
    };

    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }

    return known_gettable_ctx_params;
}

static int ardent_rand_enable_locking(ossl_unused void *seed_ctx)
{
    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }
    return 1;
}

static int ardent_rand_lock(ossl_unused void *seed_ctx)
{
    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }
    /* Operations synchronize on the shared provider-owned service lock. */
    return 1;
}

static void ardent_rand_unlock(ossl_unused void *seed_ctx)
{
    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }
}

const OSSL_DISPATCH ardent_seeding_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX,              (void(*)(void)) ardent_rand_new },
    { OSSL_FUNC_RAND_FREECTX,             (void(*)(void)) ardent_rand_free },
    { OSSL_FUNC_RAND_INSTANTIATE,         (void(*)(void)) ardent_rand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE,       (void(*)(void)) ardent_rand_uninstantiate }, 
    { OSSL_FUNC_RAND_GENERATE,            (void(*)(void)) ardent_rand_generate },
    { OSSL_FUNC_RAND_RESEED,              (void(*)(void)) ardent_rand_reseed },
    { OSSL_FUNC_RAND_ENABLE_LOCKING,      (void(*)(void)) ardent_rand_enable_locking },
    { OSSL_FUNC_RAND_LOCK,                (void(*)(void)) ardent_rand_lock },
    { OSSL_FUNC_RAND_UNLOCK,              (void(*)(void)) ardent_rand_unlock },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void(*)(void)) ardent_rand_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS,      (void(*)(void)) ardent_rand_get_ctx_params },
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION,  (void(*)(void)) ardent_rand_verify_zeroization },
    { OSSL_FUNC_RAND_GET_SEED,            (void(*)(void)) ardent_rand_get_seed },
    { OSSL_FUNC_RAND_CLEAR_SEED,          (void(*)(void)) ardent_rand_clear_seed },
    OSSL_DISPATCH_END
};

/* ***********************************************************************************************
 * ***********************************************************************************************
 * "Core" API for interop
 * ***********************************************************************************************
 * ***********************************************************************************************/
/*
EXPORT_VISIBILITY_HIDDEN
size_t ardent_core_get_entropy(void *provctx, unsigned char **pout,
                             int entropy, size_t min_len, size_t max_len)
{
    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }
    return ardent_seed_get_seed(NULL, pout, entropy, min_len, max_len, 0, NULL, 0);
}

EXPORT_VISIBILITY_HIDDEN
void ardent_core_cleanup_entropy(void *provctx, unsigned char *buf, size_t len)
{
    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }
    ardent_seed_clear_seed(NULL, buf, len);
}

EXPORT_VISIBILITY_HIDDEN
size_t ardent_core_get_nonce(void *provctx, unsigned char **pout,
                           size_t min_len, size_t max_len,
                           const void *salt, size_t salt_len)
{
    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }
    // Salt is ignored; req length 128 satisfies up to strength 256
    return ardent_seed_get_seed(NULL, pout, 128, min_len, max_len, 0, NULL, 0);
}

EXPORT_VISIBILITY_HIDDEN
void ardent_core_cleanup_nonce(void *provctx, unsigned char *buf, size_t len)
{
    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }
    ardent_seed_clear_seed(NULL, buf, len);
}

const OSSL_DISPATCH ardent_core_seed_functions[] = {
    { OSSL_FUNC_GET_ENTROPY,          (void(*)(void)) ardent_core_get_entropy },
    { OSSL_FUNC_GET_USER_ENTROPY,     (void(*)(void)) ardent_core_get_entropy },
    { OSSL_FUNC_CLEANUP_ENTROPY,      (void(*)(void)) ardent_core_cleanup_entropy },
    { OSSL_FUNC_CLEANUP_USER_ENTROPY, (void(*)(void)) ardent_core_cleanup_entropy }, 
    { OSSL_FUNC_GET_NONCE,            (void(*)(void)) ardent_core_get_nonce },
    { OSSL_FUNC_GET_USER_NONCE,       (void(*)(void)) ardent_core_get_nonce },
    { OSSL_FUNC_CLEANUP_NONCE,        (void(*)(void)) ardent_core_cleanup_nonce },
    { OSSL_FUNC_CLEANUP_USER_NONCE,   (void(*)(void)) ardent_core_cleanup_nonce },
    OSSL_DISPATCH_END
};
*/

/* ***********************************************************************************************
 * ***********************************************************************************************
 * Parameters from 'ardentmodule.cnf'
 * ***********************************************************************************************
 * ***********************************************************************************************/

static ARDENT_RESULT load_params(void* prov_ctx, ARDENT_SEEDING_CTX *ctx)
{
    const char *rbg_value = NULL;
    const char *perso_value = NULL;
    OSSL_PARAM params[3], *p = params;

    if (!prov_ctx || !ctx)
        return ARDENT_R_NULL_ARG;

    *p++ = OSSL_PARAM_construct_utf8_ptr(ARDENT_PROV_PARAM_SEED_PERSO,
                                        (char **)&perso_value,
                                        sizeof(perso_value));
    *p++ = OSSL_PARAM_construct_utf8_ptr(ARDENT_PROV_PARAM_RBG_ENTROPY_MODE,
                                        (char **) &rbg_value, 
                                        sizeof(rbg_value));
    *p = OSSL_PARAM_construct_end();

    // Load from OpenSSL Core
    if (!ardent_get_core_params(prov_ctx, params)) {
        LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_CONFIG_LOOKUP_FAILURE);
        return ARDENT_R_CONFIG_LOOKUP_FAILURE;
    }
    ctx->perso_string = perso_value;

    if (!rbg_value) {
        ardent_log(LOG_LVL_INFO, MODULE_NAME, "Entropy mode set to RBG3 (default)");
        ctx->rbg_entropy_mode = ENTROPY_MODE_RBG3;
    } else if (strncmp(rbg_value, "RBG3", 4) == 0) {
            ardent_log(LOG_LVL_INFO, MODULE_NAME, "Entropy mode set to RBG3");
        ctx->rbg_entropy_mode = ENTROPY_MODE_RBG3;
    } else if (strncmp(rbg_value, "RBG2", 4) == 0) {
            ardent_log(LOG_LVL_INFO, MODULE_NAME, "Entropy mode set to RBG2");
        ctx->rbg_entropy_mode = ENTROPY_MODE_RBG2;
    } else {
            LOG_ARDENT_ERROR(MODULE_NAME, ARDENT_R_CONFIG_PARAMETER_INVALID);
            return ARDENT_R_CONFIG_PARAMETER_INVALID;
        }
    return ARDENT_R_SUCCESS;
}

