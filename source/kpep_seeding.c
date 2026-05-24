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

#include "kpep/kpep_names.h"
#include "kpep/kpep_seed_stub.h"
#include "seeding/seed_control.h"
#include "crypto/drbg.h"
#include "kpep_internal.h"

#define MODULE_NAME "KPEP-SEED"

static SEED_CONTROL_CTX *ctrl_ctx = NULL;
static KPEP_DRBG_CTX    *drbg_ctx = NULL;

static CRYPTO_RWLOCK    *lock = NULL;

static const char       *perso_string = NULL;

//  uses one global context, but OpenSSL requires a context handle.
// Create a dummy handle to pass back to OpenSSL; ignore when passed to us
static char              dummy_char = 0xEC;
static char             *dummy_hnd = &dummy_char;

static char seed_description[SEED_CONTROL_DESCRIPTION_MAX] = { 0 };

static OSSL_FUNC_interop_fn *interop_fn = NULL;

#define RAISE_ERROR(rv) \
    if ((rv) == KPEP_R_SEED_FATAL_ERROR) { \
        ossl_set_error_state(OSSL_SELF_TEST_TYPE_CRNG); \
        ERR_raise(ERR_LIB_PROV, PROV_R_ENTROPY_SOURCE_FAILED_CONTINUOUS_TESTS); \
    } \
    else { ERR_raise(ERR_LIB_, rv); }

/* ***********************************************************************************************
 * ***********************************************************************************************
 *  Initialization and Static
 * ***********************************************************************************************
 * ***********************************************************************************************/

static KPEP_RESULT load_params(void* prov_ctx);

EXPORT_VISIBILITY_HIDDEN
void kpep_seeding_fini(void)
{
    if (drbg_ctx) {
        drbg_uninstantiate(drbg_ctx);
        drbg_free(drbg_ctx);
        drbg_ctx = NULL;
    }
    if (ctrl_ctx) {
        seed_control_free(ctrl_ctx);
        ctrl_ctx = NULL;
    }
    CRYPTO_THREAD_lock_free(lock);
}

EXPORT_VISIBILITY_HIDDEN
KPEP_RESULT kpep_seeding_init(void* prov_ctx)
{
    KPEP_RESULT rv = KPEP_R_SUCCESS;
    uint32_t state;

    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: Seed subsystem Init\n", MODULE_NAME);
    #endif

    // Pull runtime configuration from params
    rv = load_params(prov_ctx);
    if (rv) {
        LOG_KPEP_ERROR(MODULE_NAME, rv);
        goto err;
    }
    
    // Setup Seed Control
    ctrl_ctx = seed_control_new(prov_ctx, &rv);
    if (rv) {
        LOG_KPEP_ERROR(MODULE_NAME, rv);
        goto err;
    }
    state = seed_control_get_state(ctrl_ctx);
    if (state != KPEP_RAND_STATE_READY) {
        if (state == KPEP_RAND_STATE_UNINITIALISED)
            rv = KPEP_R_SEED_NOT_INSTANTIATED;
        else if (state == KPEP_RAND_STATE_ERROR)
            rv = KPEP_R_SEED_IN_ERROR_STATE;
        goto err;
    }

    // Setup DRBG
    drbg_ctx = drbg_new(ctrl_ctx, &rv);
    if (rv) {
        LOG_KPEP_ERROR(MODULE_NAME, rv);
        goto err;
    }
    rv = drbg_instantiate(drbg_ctx, KPEP_SECURITY_STRENGTH_BITS, 
                          (uint8_t*)perso_string, perso_string?strlen(perso_string):0);
    if (rv) {
        LOG_KPEP_ERROR(MODULE_NAME, rv);
        goto err;
    }

err:
    if (rv) {
        kpep_seeding_fini();
        RAISE_ERROR(rv);
    }

    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: Seed subsystem Init Complete\n", MODULE_NAME);
    #endif

    return rv;
}

EXPORT_VISIBILITY_HIDDEN
const char* kpep_seeding_get_description(void)
{
    seed_control_get_description(ctrl_ctx, seed_description);
    return seed_description;
}

EXPORT_VISIBILITY_HIDDEN
int kpep_seeding_get_restricted_mode(void)
{
    return seed_control_get_restricted_mode(ctrl_ctx);
}

EXPORT_VISIBILITY_HIDDEN
void kpep_set_kpep_seeding_interop_fn(OSSL_FUNC_interop_fn *fn)
{
    interop_fn = fn;
}

/* ***********************************************************************************************
 * ***********************************************************************************************
 * DRBG INTERFACE
 * ***********************************************************************************************
 * ***********************************************************************************************/

static void *kpep_seed_new(void *provctx, void *parent,
                        const OSSL_DISPATCH *parent_dispatch)
{
    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif

    if (parent != NULL) {
        RAISE_ERROR(PROV_R_SEED_SOURCES_MUST_NOT_HAVE_A_PARENT);
        return NULL;
    }

    return dummy_hnd;
}

static void kpep_seed_free(void *seed_ctx)
{
    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif
}

static int kpep_seed_instantiate(void *seed_ctx, unsigned int strength,
                              int prediction_resistance,
                              const unsigned char *pstr,
                              size_t pstr_len,
                              ossl_unused const OSSL_PARAM params[])
{
    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif

    return 1;
}

static int kpep_seed_uninstantiate(void *seed_ctx)
{
    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif

    return 1;
}

static int kpep_seed_generate(void *seed_ctx, unsigned char *out, size_t outlen,
                           unsigned int strength,
                           ossl_unused int prediction_resistance,
                           ossl_unused const unsigned char *adin,
                           ossl_unused size_t adin_len)
{
    KPEP_RESULT rv = KPEP_R_SUCCESS;
    uint32_t state;
    
    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s (req %lu)\n", MODULE_NAME, __func__, outlen<<3);
    #endif

    // Ensure provider is not in error state
    if (!ossl_prov_is_running() || (interop_fn && !interop_fn()))
        return 0;

    // Check seed state
    state = seed_control_get_state(ctrl_ctx);
    if (state != KPEP_RAND_STATE_READY) {
        RAISE_ERROR(state == KPEP_RAND_STATE_ERROR ? PROV_R_IN_ERROR_STATE
                                                   : PROV_R_NOT_INSTANTIATED);
        return 0;
    }

    // Generate
    rv = drbg_generate(drbg_ctx, out, outlen);
    if (rv) {
        // Error logged in DRBG/Seed-source
        RAISE_ERROR(rv);
        return 0;
    }

    return outlen;
}

static int kpep_seed_reseed(ossl_unused void *seed_ctx,
                            ossl_unused int prediction_resistance,
                            ossl_unused const unsigned char *ent,
                            ossl_unused size_t ent_len,
                            ossl_unused const unsigned char *adin,
                            ossl_unused size_t adin_len)
{
    uint32_t state;

    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif

    // Ensure provider is not in error state
    if (!ossl_prov_is_running() || (interop_fn && !interop_fn()))
        return 0;

    // Check seed state
    state = seed_control_get_state(seed_ctx);
    if (state != KPEP_RAND_STATE_READY) {
        RAISE_ERROR(state == KPEP_RAND_STATE_ERROR ? PROV_R_IN_ERROR_STATE
                                                   : PROV_R_NOT_INSTANTIATED);
        return 0;
    }
    return 1;
}

static int kpep_seed_get_ctx_params(ossl_unused void *seed_ctx, OSSL_PARAM params[])
{
    uint32_t state;
    OSSL_PARAM *p;

    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif

    state = seed_control_get_state(ctrl_ctx);

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p != NULL && !OSSL_PARAM_set_int(p, state))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_int(p, KPEP_SECURITY_STRENGTH_BITS))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, DRBG_MAX_BYTES_PER_REQUEST))
        return 0;
    return 1;
}

static const OSSL_PARAM *kpep_seed_gettable_ctx_params(ossl_unused void *seed_ctx,
                                                       ossl_unused void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END
    };

    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif

    return known_gettable_ctx_params;
}

static int kpep_seed_verify_zeroization(ossl_unused void *seed_ctx)
{
    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif

    if (!drbg_ctx)
        return 1;
    return drbg_verify_zeroization(drbg_ctx);
}
 
static size_t kpep_seed_get_seed(ossl_unused void *seed_ctx, unsigned char **pout,
                               int entropy, size_t min_len,
                               size_t max_len,
                               int prediction_resistance,
                               const unsigned char *adin,
                               size_t adin_len)
{
    KPEP_RESULT rv = KPEP_R_SUCCESS;

    unsigned char *buffer = NULL;
    size_t         buflen = 0;
    size_t         requested = (size_t) entropy;
    uint32_t       state;
    
    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif

    if (!ctrl_ctx || !drbg_ctx || !pout)
        return 0;
    if (!entropy)
        return 0;

    // Ensure provider is not in error state
    if (!ossl_prov_is_running() || (interop_fn && !interop_fn()))
        return 0;

    // Check seed state
    state = seed_control_get_state(ctrl_ctx);
    if (state != KPEP_RAND_STATE_READY) {
        RAISE_ERROR(state == KPEP_RAND_STATE_ERROR ? PROV_R_IN_ERROR_STATE
                                                   : PROV_R_NOT_INSTANTIATED);
        return 0;
    }

    // Set requested length with min/max enforcement
    buflen = (requested < min_len)?min_len:
             (requested > max_len)?max_len:requested;

    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: request (%lu<%lu<%lu=%lu)\n", MODULE_NAME, min_len, requested, max_len, buflen);
    #endif

    buffer = kpep_zalloc(buflen);
    if (!buffer) {
        LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_MALLOC_FAIL);
        RAISE_ERROR(KPEP_R_MALLOC_FAIL);
        return 0;
    }

    rv = drbg_generate(drbg_ctx, buffer, buflen);
    if (rv) {
        // Error logged in DRBG/Seed-source
        kpep_cleanse(buffer, buflen);
        RAISE_ERROR(rv);
        return 0;
    }

    *pout = buffer;
    return buflen;
}
 
static void kpep_seed_clear_seed(ossl_unused void *seed_ctx,
                               unsigned char *out, size_t outlen)
{
    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif

    OPENSSL_cleanse(out, outlen);
}
 
static int kpep_seed_enable_locking(void *seed_ctx)
{
    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif

    if (seed_ctx && !lock) {
        lock = CRYPTO_THREAD_lock_new();
        if (lock == NULL) {
            RAISE_ERROR(RAND_R_FAILED_TO_CREATE_LOCK);
            return 0;
        }
    }
    return 1;
}

static int kpep_seed_lock(void *seed_ctx)
{
    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif

    if (!seed_ctx || !lock)
        return 1;
    return CRYPTO_THREAD_write_lock(lock);
}

static void kpep_seed_unlock(void *seed_ctx)
{
    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif

    if (seed_ctx && lock)
        CRYPTO_THREAD_unlock(lock);
}

const OSSL_DISPATCH kpep_seeding_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX,              (void(*)(void)) kpep_seed_new },
    { OSSL_FUNC_RAND_FREECTX,             (void(*)(void)) kpep_seed_free },
    { OSSL_FUNC_RAND_INSTANTIATE,         (void(*)(void)) kpep_seed_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE,       (void(*)(void)) kpep_seed_uninstantiate }, 
    { OSSL_FUNC_RAND_GENERATE,            (void(*)(void)) kpep_seed_generate },
    { OSSL_FUNC_RAND_RESEED,              (void(*)(void)) kpep_seed_reseed },
    { OSSL_FUNC_RAND_ENABLE_LOCKING,      (void(*)(void)) kpep_seed_enable_locking },
    { OSSL_FUNC_RAND_LOCK,                (void(*)(void)) kpep_seed_lock },
    { OSSL_FUNC_RAND_UNLOCK,              (void(*)(void)) kpep_seed_unlock },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void(*)(void)) kpep_seed_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS,      (void(*)(void)) kpep_seed_get_ctx_params },
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION,  (void(*)(void)) kpep_seed_verify_zeroization },
    { OSSL_FUNC_RAND_GET_SEED,            (void(*)(void)) kpep_seed_get_seed },
    { OSSL_FUNC_RAND_CLEAR_SEED,          (void(*)(void)) kpep_seed_clear_seed },
    OSSL_DISPATCH_END
};

EXPORT_VISIBILITY_HIDDEN
size_t kpep_core_get_entropy(void *provctx, unsigned char **pout,
                             int entropy, size_t min_len, size_t max_len)
{
    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif
    return kpep_seed_get_seed(NULL, pout, entropy, min_len, max_len, 0, NULL, 0);
}

EXPORT_VISIBILITY_HIDDEN
void kpep_core_cleanup_entropy(void *provctx, unsigned char *buf, size_t len)
{
    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif
    kpep_seed_clear_seed(NULL, buf, len);
}

EXPORT_VISIBILITY_HIDDEN
size_t kpep_core_get_nonce(void *provctx, unsigned char **pout,
                           size_t min_len, size_t max_len,
                           const void *salt, size_t salt_len)
{
    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif
    // Salt is ignored; req length 128 satisfies up to strength 256
    return kpep_seed_get_seed(NULL, pout, 128, min_len, max_len, 0, NULL, 0);
}

EXPORT_VISIBILITY_HIDDEN
void kpep_core_cleanup_nonce(void *provctx, unsigned char *buf, size_t len)
{
    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif
    kpep_seed_clear_seed(NULL, buf, len);
}

const OSSL_DISPATCH kpep_core_seed_functions[] = {
    { OSSL_FUNC_GET_ENTROPY,          (void(*)(void)) kpep_core_get_entropy },
    { OSSL_FUNC_GET_USER_ENTROPY,     (void(*)(void)) kpep_core_get_entropy },
    { OSSL_FUNC_CLEANUP_ENTROPY,      (void(*)(void)) kpep_core_cleanup_entropy },
    { OSSL_FUNC_CLEANUP_USER_ENTROPY, (void(*)(void)) kpep_core_cleanup_entropy }, 
    { OSSL_FUNC_GET_NONCE,            (void(*)(void)) kpep_core_get_nonce },
    { OSSL_FUNC_GET_USER_NONCE,       (void(*)(void)) kpep_core_get_nonce },
    { OSSL_FUNC_CLEANUP_NONCE,        (void(*)(void)) kpep_core_cleanup_nonce },
    { OSSL_FUNC_CLEANUP_USER_NONCE,   (void(*)(void)) kpep_core_cleanup_nonce },
    OSSL_DISPATCH_END
};

/* ***********************************************************************************************
 * ***********************************************************************************************
 * Parameters from 'kpepmodule.cnf'
 * ***********************************************************************************************
 * ***********************************************************************************************/

static KPEP_RESULT load_params(void* prov_ctx)
{
    // Configuration items to read
    OSSL_PARAM params[2], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        KPEP_PROV_PARAM_SEED_PERSO,
        (char **) &perso_string,
        sizeof(perso_string));
    *p = OSSL_PARAM_construct_end();

    // Load from OpenSSL Core
    if (!kpep_get_core_params(prov_ctx, params)) {
        LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_CONFIG_LOOKUP_FAILURE);
        return KPEP_R_CONFIG_LOOKUP_FAILURE;
    }

    return KPEP_R_SUCCESS;
}
