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
 * ***********************************************************************************************
 * REFERENCE DOCS:
 * 
 * https://www.openssl.org/docs/manmaster/man7/provider.html
 * https://www.openssl.org/docs/manmaster/man7/provider-base.html
 * 
 * ***********************************************************************************************/

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

#include "openssl/provider.h"       /* Base provider API */
/* Embedded includes from provider.h:
#  include <openssl/core.h>
#  include <openssl/types.h> 
#  include <openssl/e_os2.h>
#  include <openssl/macros.h>
#  include <openssl/opensslconf.h>
#  include <openssl/configuration.h>
#  include <openssl/opensslv.h>
#  include <openssl/safestack.h>
*/
#include "openssl/core_names.h"       /* Algorithm names and IDs */
#include "openssl/core_dispatch.h"    /* OSSL Functions */
#include "openssl/params.h"           /* Provider Parameters */
#include "openssl/bio.h"              /* BIO system */
#include "openssl/err.h"              /* Error handling */
#include "openssl/proverr.h"          /* More Error handling */
#include "prov/provider_ctx.h"        /* Access inside provider context structure */
#include "internal/cryptlib.h"

#include "ardent/ardent.h"                /* Module properties strings for fetch */
#include "ardent/ardent_names.h"          /* Parameter and configuration names */
#include "ardent_bio.h"                 /* OpenSSL BIO routines */
#include "ardent_internal.h"            /* Subsystem declarations */
#include "ardent_self_test.h"           /* Self Testing */

#include "crypto/sha2.h"              /* SHA2-256 functions */
#include "crypto/sha3.h"              /* SHA3-256 functions */
#include "crypto/hmac.h"              /* HMAC functions */

/* ************************************************************************************************
 * ************************************************************************************************
 *  DECLARATIONS 
 * ************************************************************************************************
 * ***********************************************************************************************/
// Top-level identification
#define ARDENT_PROVIDER_MODULE_NAME "ARDent Entropy Provider for OpenSSL"
#define ARDENT_PROVIDER_VERSION_STR "0.8.9-dev"
#define ARDENT_PROVIDER_BUILDINFO_STR "ARDENT_" ARDENT_PROVIDER_VERSION_STR

#define MODULE_NAME "ARDENT-PROV"

typedef struct ardent_provider_ctx_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX           *libctx;         /* For all provider modules */
    BIO_METHOD             *corebiometh; 
    SELF_TEST_PARAMS       *st;
    ARDENT_SEEDING_CTX       *seeding;
} ARDENT_PROVIDER_CTX;

EXPORT_VISIBILITY_HIDDEN
ARDENT_SEEDING_CTX *ardent_provider_get_seeding(void *prov_ctx)
{
    ARDENT_PROVIDER_CTX *ctx = (ARDENT_PROVIDER_CTX *)prov_ctx;
    return ctx ? ctx->seeding : NULL;
}

/* Forward declarations to ensure that interface functions are correctly defined */
static OSSL_FUNC_provider_teardown_fn         ardent_teardown;
static OSSL_FUNC_provider_gettable_params_fn  ardent_gettable_params;
static OSSL_FUNC_provider_get_params_fn       ardent_get_params;
static OSSL_FUNC_provider_query_operation_fn  ardent_query;

/* Register threads for monitoring stop notice. See comments in crypto/initthread.c */
extern OSSL_FUNC_core_thread_start_fn        *c_thread_start;
EXPORT_VISIBILITY_HIDDEN
       OSSL_FUNC_core_thread_start_fn        *c_thread_start;

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn     *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn          *c_get_params = NULL;
static OSSL_FUNC_core_get_libctx_fn          *c_get_libctx = NULL;
static OSSL_FUNC_self_test_cb_fn             *c_stcbfn = NULL;

/* ************************************************************************************************
 * ************************************************************************************************
 * FIPS INDICATOR LOGGING
 * ************************************************************************************************
 * ***********************************************************************************************/

/* A callback that is triggered if fips unapproved mode is detected */
static int fips_indicator_cb(const char *type, const char *desc, const OSSL_PARAM params[])
{
#ifdef FIPS_OPTEST
    printf("CALLBACK: %s : %s\n", type, desc);
#endif
    ardent_log(LOG_LVL_INFO, MODULE_NAME, "FIPS-IND: %s : %s", type, desc);
    return 1;  // 1 to allow, 0 to force an error
}

/* ************************************************************************************************
 * ************************************************************************************************
 * PROVIDER PARAMETERS -- LOAD-FROM-CORE and APP-FACING
 * ************************************************************************************************
 * ***********************************************************************************************/

/* *** LOAD-FROM-CORE (read from config file *****************************************************/

EXPORT_VISIBILITY_DEFAULT
int ardent_get_core_params(void *ctx, void *params)
{
    ARDENT_PROVIDER_CTX *prov_ctx = (ARDENT_PROVIDER_CTX *)ctx;
    return c_get_params(prov_ctx->handle, (OSSL_PARAM *)params);
}

EXPORT_VISIBILITY_DEFAULT
int ardent_get_core_param_bool(void *ctx, const char *name, int defval)
{
    ARDENT_PROVIDER_CTX *prov_ctx = (ARDENT_PROVIDER_CTX *)ctx;
    OSSL_PROVIDER     *prov = (OSSL_PROVIDER*) prov_ctx->handle;
    return OSSL_PROVIDER_conf_get_bool(prov, name, defval);
}

static int ardent_get_params_from_core(ARDENT_PROVIDER_CTX *ctx)
{
    const char *str_indicator = NULL;
    /*
    * Parameters to retrieve from the core provider - required for self testing.
    * NOTE: inside core_get_params() these will be loaded from config items
    * stored inside prov->parameters (except for OSSL_PROV_PARAM_CORE_MODULE_FILENAME).
    */
    OSSL_PARAM core_params[4], *p = core_params;
    *p++ = OSSL_PARAM_construct_utf8_ptr(
            OSSL_PROV_PARAM_CORE_MODULE_FILENAME,
            (char **)&ctx->st->module_filename,
            sizeof(ctx->st->module_filename));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
            ARDENT_PROV_PARAM_MODULE_MAC,
            (char **)&ctx->st->module_mac_data,
            sizeof(ctx->st->module_mac_data));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
            ARDENT_PROV_PARAM_LOG_FIPS_INDICATORS,
            (char **)&str_indicator,
            sizeof(str_indicator));            
    *p = OSSL_PARAM_construct_end();

    if (!c_get_params(ctx->handle, core_params)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }

    // Check for flag to log FIPS indicators
//    if (str_indicator && !strncmp(str_indicator, "1", 1)) {
//        OSSL_INDICATOR_set_callback((OSSL_LIB_CTX *)c_get_libctx(ctx->handle), fips_indicator_cb);
//    }

    return 1;
}

/* *** APP-FACING (parameters we provide to the core/app) ****************************************/

static const OSSL_PARAM ardent_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_DEFN(ARDENT_PROV_PARAM_RESTRICTED_MODE, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_DEFN(ARDENT_PROV_PARAM_SEED_SOURCES, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ardent_gettable_params(void *provctx)
{
    return ardent_param_types;
}

static int ardent_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    ARDENT_PROVIDER_CTX *ctx = (ARDENT_PROVIDER_CTX*)provctx;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ARDENT_PROVIDER_MODULE_NAME))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ARDENT_PROVIDER_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ARDENT_PROVIDER_BUILDINFO_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
        return 0;
    p = OSSL_PARAM_locate(params, ARDENT_PROV_PARAM_RESTRICTED_MODE);
    if (p != NULL && !OSSL_PARAM_set_int(p, ardent_seeding_get_restricted_mode(ctx->seeding)))
        return 0;
    p = OSSL_PARAM_locate(params, ARDENT_PROV_PARAM_SEED_SOURCES);
    if (p != NULL) {
        const char *desc = ardent_seeding_get_description(ctx->seeding);
        if (!OSSL_PARAM_set_utf8_ptr(p, desc))
            return 0;
    }
    return 1;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * OpenSSL RAND_bytes() infrastructure
 * ************************************************************************************************
 * ***********************************************************************************************/
/*
extern const OSSL_DISPATCH ardent_seeding_functions[];

static int ardent_random_bytes(void *vprov, int which,
                             void *buf, size_t n, unsigned int strength) 
{
    ARDENT_PROVIDER_CTX *prov_ctx = (ARDENT_PROVIDER_CTX *)vprov;
    const OSSL_DISPATCH *disp = ardent_seeding_functions;
    static OSSL_FUNC_rand_generate_fn *generate_fn = NULL;

    if (ardent_trace_seed_enabled) {
        TRACE_START;
    }

    // Ensure provider is not in error state
    if (!ossl_prov_is_running())
        return 0;

    // First call, load the generate function
    if (!generate_fn) {
        while (disp && disp->function_id) {
            if (disp->function_id == OSSL_FUNC_RAND_GENERATE) {
                generate_fn = (OSSL_FUNC_rand_generate_fn*) disp->function;
                break;
            }
            disp++;
        }
    }

    if (generate_fn)
        return (generate_fn(vprov, buf, n, 256, 0, NULL, 0) == (int)n);
    else
        return -1;
}
*/
/* ************************************************************************************************
 * ************************************************************************************************
 * SELF-TEST INFRASTRUCTURE
 * ************************************************************************************************
 * ***********************************************************************************************/

static void set_self_test_cb(ARDENT_PROVIDER_CTX *ctx)
{
    if (c_stcbfn != NULL && c_get_libctx != NULL) {
        c_stcbfn(c_get_libctx(ctx->handle), 
                 &ctx->st->cb,
                 &ctx->st->cb_arg);
    } else {
        ctx->st->cb = NULL;
        ctx->st->cb_arg = NULL;
    }
}

static int ardent_self_test(void *provctx)
{
    ARDENT_PROVIDER_CTX *ctx = (ARDENT_PROVIDER_CTX*)provctx;
    set_self_test_cb(ctx); 
    return !!SELF_TEST_post(ctx->st, 1);  // on-demand
}

/* ************************************************************************************************
 * ************************************************************************************************
 * SUPPORTED ALGORITHMS
 * ************************************************************************************************
 * ***********************************************************************************************/

 /* 
 * Strings for fetch of algorithms the module supports.
 * Copied from OSSL3 header file "names.h"
 */
#define ARDENT_NAMES_HMAC      "HMAC"
#define ARDENT_NAMES_SHA2_256  "SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1"
#define ARDENT_NAMES_SHA3_256  "SHA3-256:2.16.840.1.101.3.4.2.8"
#define ARDENT_NAMES_SEED      "ARDENT-SEED"
#define DEFAULT_NAMES_SEED   "SEED-SRC"  // This is hardcoded and not in "names.h"

EXPORT_VISIBILITY_HIDDEN
extern const OSSL_DISPATCH ardent_sha2_digest_functions[];
EXPORT_VISIBILITY_HIDDEN
extern const OSSL_DISPATCH ardent_sha3_digest_functions[];
EXPORT_VISIBILITY_HIDDEN
extern const OSSL_DISPATCH ardent_hmac_functions[];
EXPORT_VISIBILITY_HIDDEN
extern const OSSL_DISPATCH ardent_seeding_functions[];

static const OSSL_ALGORITHM ardent_rands[] = {
    { DEFAULT_NAMES_SEED, ARDENT_MODULE_PROPERTIES, ardent_seeding_functions, NULL }, // OpenSSL default seed name
    { ARDENT_NAMES_SEED, ARDENT_MODULE_PROPERTIES, ardent_seeding_functions, NULL },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM ardent_digests[] = {
    { ARDENT_NAMES_SHA2_256, ARDENT_MODULE_PROPERTIES, ardent_sha2_digest_functions, NULL },
    { ARDENT_NAMES_SHA3_256, ARDENT_MODULE_PROPERTIES, ardent_sha3_digest_functions, NULL },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM ardent_macs[] = {
    { ARDENT_NAMES_HMAC, ARDENT_MODULE_PROPERTIES, ardent_hmac_functions, NULL },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *ardent_query(void *provctx, int operation_id, int *no_cache)
{
    ARDENT_PROVIDER_CTX *ctx = (ARDENT_PROVIDER_CTX*) provctx;
    *no_cache = 1;  // Do NOT cache the algorithms

    if (!ossl_prov_is_running())
        return NULL;

    switch (operation_id) {
    case OSSL_OP_RAND:
        return ardent_rands;
#ifdef FIPS_ACVP
    case OSSL_OP_DIGEST:
        return ardent_digests;
    case OSSL_OP_MAC:
        return ardent_macs;
#endif
    }
   return NULL;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * PROVIDER FUNCTIONS -- INIT, DISPATCH, TEARDOWN, ETC
 * ************************************************************************************************
 * ***********************************************************************************************/

static ARDENT_PROVIDER_CTX *ardent_ctx_new(OSSL_LIB_CTX *libctx, 
                                          const OSSL_CORE_HANDLE *handle, 
                                          BIO_METHOD *bm) 
{
    ARDENT_PROVIDER_CTX *ctx;

    ctx = (ARDENT_PROVIDER_CTX*) ardent_zalloc(sizeof(ARDENT_PROVIDER_CTX));
    if (!ctx)
        return NULL;

    /* Self-Test params */
    ctx->st = (SELF_TEST_PARAMS*) ardent_zalloc(sizeof(SELF_TEST_PARAMS));
    if (!ctx->st) {
        ardent_free(ctx);
        return NULL;
    }
    ctx->st->libctx = libctx;

    /* Global handles */
    ctx->handle = handle;
    ctx->libctx = libctx;
    ctx->corebiometh = bm;

    return ctx;
}

static void ardent_ctx_free(ARDENT_PROVIDER_CTX *ctx) 
{
    if (!ctx) 
        return;
    
    if (ctx->corebiometh)
        BIO_meth_free(ctx->corebiometh);
    if (ctx->st)
        ardent_cleanse(ctx->st, sizeof(SELF_TEST_PARAMS));
    if (ctx->libctx)
        OSSL_LIB_CTX_free(ctx->libctx);
    ardent_cleanse(ctx, sizeof(ARDENT_PROVIDER_CTX));
    ardent_log(LOG_LVL_INFO, MODULE_NAME, "Provider teardown complete");
}

static void ardent_teardown(void *provctx)
{
    ARDENT_PROVIDER_CTX *ctx = (ARDENT_PROVIDER_CTX*)provctx;

	if (!ctx)
		return;

    ardent_seeding_free(ctx->seeding);
	ardent_debug_fini();  // Trace teardown stays after seeding; core cleanup happens here
	ardent_logging_fini(); // Must be last so all messages are flushed
    ardent_ctx_free((ARDENT_PROVIDER_CTX*)provctx);
}

/* Functions we provide to the core */
static const OSSL_DISPATCH ardent_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN,         (void (*)(void))ardent_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,  (void (*)(void))ardent_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,       (void (*)(void))ardent_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,  (void (*)(void))ardent_query },
    { OSSL_FUNC_PROVIDER_SELF_TEST,        (void (*)(void))ardent_self_test },
//    { OSSL_FUNC_PROVIDER_RANDOM_BYTES,     (void (*)(void))ardent_random_bytes },
    { 0, NULL }
};

/* Required initialization function */
EXPORT_VISIBILITY_DEFAULT
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    const OSSL_DISPATCH *orig_in = in;
    ARDENT_RESULT rv = ARDENT_R_SUCCESS;

    ARDENT_PROVIDER_CTX *newctx = NULL;
    BIO_METHOD *corebiometh;
    OSSL_LIB_CTX *libctx = NULL;
    int result = 0;

    // Debug should be active for provider startup, and it must reflect the current env state.
    ardent_debug_init();

    if (ardent_trace_seed_enabled) {
        ardent_trace(MODULE_NAME, "Provider Init Start");
    }

    // Load our error strings into OpenSSL
    if (!ardent_set_openssl_reason_strings()) {
        ERR_raise(ERR_LIB_PROV, PROV_R_VALUE_ERROR);
    }

    // Output a log message about startup, if the config calls for logging (peek at config)
    if (OSSL_PROVIDER_conf_get_bool((void*)handle, ARDENT_PROV_PARAM_LOG_SYSLOG_ACTIVATE, 0)) {
        syslog(LOG_LVL_INFO, MODULE_NAME": Provider startup initialized\n");
    }
    if (OSSL_PROVIDER_conf_get_bool((void*)handle, ARDENT_PROV_PARAM_LOG_STDERR_ACTIVATE, 0)) {
        fprintf(stderr, "%s", MODULE_NAME": Provider startup initialized\n");
    }

    /* Pull core functions reated to BIO (at bottom of file) */
    if (!ardent_bio_from_dispatch(in))
        goto ret;
    
    /* Pull core functions the provider is interested in */
    for (; in->function_id != 0; in++) {
        #define set_func(c, f) if (c == NULL) c = f; else if (c != f) return 0;

        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBCTX:
            set_func(c_get_libctx, OSSL_FUNC_core_get_libctx(in));
            break;
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            set_func(c_gettable_params, OSSL_FUNC_core_gettable_params(in));
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            set_func(c_get_params, OSSL_FUNC_core_get_params(in));
            break;
        case OSSL_FUNC_CORE_THREAD_START:
            set_func(c_thread_start, OSSL_FUNC_core_thread_start(in));
            break;
        case OSSL_FUNC_SELF_TEST_CB:
            set_func(c_stcbfn, OSSL_FUNC_self_test_cb(in));
			break;
        /* Just ignore anything we don't understand */
        default:
            break;
        }
    }

    // if libctx not yet existing, create a new one
    if ((corebiometh = ardent_bio_prov_init_bio_method()) == NULL) {
        ardent_log(LOG_LVL_ERR, MODULE_NAME, "Error creating new BIO handle\n");
    	goto ret;
    }

    if ((libctx = OSSL_LIB_CTX_new_child(handle, orig_in)) == NULL) { 
        ardent_log(LOG_LVL_ERR, MODULE_NAME, "Error creating new library context\n");
        BIO_meth_free(corebiometh);
    	goto ret;
    }

    if ((newctx = ardent_ctx_new(libctx, handle, corebiometh)) == NULL ) { 
        ardent_log(LOG_LVL_ERR, MODULE_NAME, "Error creating new provider context\n");
        BIO_meth_free(corebiometh);
        OSSL_LIB_CTX_free(libctx);
    	goto ret;
    }
    newctx->corebiometh = corebiometh;
    newctx->libctx = libctx;

    // Load our configuration from the core
    if (!ardent_get_params_from_core(newctx)) {
        // Error already raised
        goto err;
    }

    // Crypto algorithm Self-Tests
    if (!SELF_TEST_post(newctx->st, 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_POST_FAILURE);
        goto err; 
    }

    // Initialize all subsystems
    rv = ardent_logging_init(newctx);  // Make into context!
    if (rv) {
        ERR_raise(ERR_LIB_ARDENT, rv);
        goto err;
    }
    newctx->seeding = ardent_seeding_new(newctx);
    if (!newctx->seeding) {
        ardent_log(LOG_LVL_ERR, MODULE_NAME, "Error initializing seeding subsystem\n");
        ERR_raise(ERR_LIB_ARDENT, ARDENT_R_SEED_INIT_FAIL);
        goto err;
    }
	// TODO: Log error "some subsystems failed to start"?

    // Start the immutable-configured runtime debug listener after provider startup.
    ardent_debug_control_init(newctx);

    // Signal success
    *out = ardent_dispatch_table;
    *provctx = newctx;
    result = 1;

err:
    if (!result) {
        ardent_teardown(newctx);
        *provctx = NULL;
    }

    ardent_log(LOG_LVL_INFO, MODULE_NAME, "Provider startup complete (%s)", result?"PASS":"FAIL");

ret:
    if (ardent_trace_seed_enabled) {
        ardent_trace(MODULE_NAME, "Provider Init Complete");
    }

    return result;
}

EXPORT_VISIBILITY_HIDDEN
BIO *ardent_bio_new_from_core_bio(void *provctx, OSSL_CORE_BIO *corebio)
{
    BIO *outbio;
    BIO_METHOD *corebiometh = ((ARDENT_PROVIDER_CTX *) provctx)->corebiometh;

    if (corebiometh == NULL)
        return NULL;

    if ((outbio = BIO_new(corebiometh)) == NULL)
        return NULL;
    if (!ardent_bio_up_ref(corebio)) {
        BIO_free(outbio);
        return NULL;
    }
    BIO_set_data(outbio, corebio);
    return outbio;
}

