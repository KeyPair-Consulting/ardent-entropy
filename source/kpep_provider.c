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
#include "internal/cryptlib.h"
#include "openssl/core_names.h"       /* Algorithm names and IDs */
#include "openssl/core_dispatch.h"    /* OSSL Functions */
#include "openssl/params.h"           /* Provider Parameters */
#include "openssl/bio.h"              /* BIO system */
#include "openssl/err.h"              /* Error handling */
#include "openssl/proverr.h"          /* More Error handling */
#include "prov/provider_ctx.h"        /* Access inside provider context structure */

#include "kpep/kpep.h"                /* Module properties strings for fetch */
#include "kpep/kpep_names.h"          /* Parameter and configuration names */
#include "kpep_bio.h"                 /* OpenSSL BIO routines */
#include "kpep_internal.h"            /* Subsystem declarations */
#include "kpep_self_test.h"                /* Self Testing */

#include "crypto/sha2.h"              /* SHA2-256 functions */
#include "crypto/sha3.h"              /* SHA3-256 functions */
#include "crypto/hmac.h"              /* HMAC functions */

/* ************************************************************************************************
 * ************************************************************************************************
 *  DECLARATIONS 
 * ************************************************************************************************
 * ***********************************************************************************************/
// Top-level identification
#define KPEP_PROVIDER_MODULE_NAME "KeyPair Entropy Provider for OpenSSL"
#define KPEP_PROVIDER_VERSION_STR "0.0.2-dev"
#define KPEP_PROVIDER_BUILDINFO_STR "KPEP_" KPEP_PROVIDER_VERSION_STR

#define MODULE_NAME "KPEP-PROV"

typedef struct kpep_provider_ctx_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX           *libctx;         /* For all provider modules */
    BIO_METHOD             *corebiometh; 
    SELF_TEST_PARAMS       *st;
} KPEP_PROVIDER_CTX;

/* Forward declarations to ensure that interface functions are correctly defined */
static OSSL_FUNC_provider_teardown_fn         kpep_teardown;
static OSSL_FUNC_provider_gettable_params_fn  kpep_gettable_params;
static OSSL_FUNC_provider_get_params_fn       kpep_get_params;
static OSSL_FUNC_provider_query_operation_fn  kpep_query;

/* Register threads for monitoring stop notice. See comments in crypto/initthread.c */
extern OSSL_FUNC_core_thread_start_fn        *c_thread_start;
EXPORT_VISIBILITY_HIDDEN
       OSSL_FUNC_core_thread_start_fn        *c_thread_start;

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn     *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn          *c_get_params = NULL;
static OSSL_FUNC_BIO_new_file_fn             *c_bio_new_file = NULL;
static OSSL_FUNC_BIO_new_membuf_fn           *c_bio_new_membuf = NULL;
static OSSL_FUNC_BIO_read_ex_fn              *c_bio_read_ex = NULL;
static OSSL_FUNC_BIO_write_ex_fn             *c_bio_write_ex = NULL;
static OSSL_FUNC_BIO_gets_fn                 *c_bio_gets = NULL;
static OSSL_FUNC_BIO_puts_fn                 *c_bio_puts = NULL;
static OSSL_FUNC_BIO_ctrl_fn                 *c_bio_ctrl = NULL;
static OSSL_FUNC_BIO_up_ref_fn               *c_bio_up_ref = NULL;
static OSSL_FUNC_BIO_free_fn                 *c_bio_free = NULL;
static OSSL_FUNC_BIO_vprintf_fn              *c_bio_vprintf = NULL;
static OSSL_FUNC_self_test_cb_fn             *c_stcbfn = NULL;
static OSSL_FUNC_core_get_libctx_fn          *c_get_libctx = NULL;

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
    kpep_log(LOG_LVL_INFO, MODULE_NAME, "FIPS-IND: %s : %s", type, desc);
    return 1;  // 1 to allow, 0 to force an error
}

/* ************************************************************************************************
 * ************************************************************************************************
 * PROVIDER PARAMETERS -- LOAD-FROM-CORE and APP-FACING
 * ************************************************************************************************
 * ***********************************************************************************************/

/* *** LOAD-FROM-CORE (read from config file *****************************************************/

EXPORT_VISIBILITY_DEFAULT
int kpep_get_core_params(void *ctx, void *params)
{
    KPEP_PROVIDER_CTX *prov_ctx = (KPEP_PROVIDER_CTX *)ctx;
    return c_get_params(prov_ctx->handle, (OSSL_PARAM *)params);
}

EXPORT_VISIBILITY_DEFAULT
int kpep_get_core_param_bool(void *ctx, const char *name, int defval)
{
    KPEP_PROVIDER_CTX *prov_ctx = (KPEP_PROVIDER_CTX *)ctx;
    OSSL_PROVIDER     *prov = (OSSL_PROVIDER*) prov_ctx->handle;
    return OSSL_PROVIDER_conf_get_bool(prov, name, defval);
}

static int kpep_get_params_from_core(KPEP_PROVIDER_CTX *ctx)
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
            KPEP_PROV_PARAM_MODULE_MAC,
            (char **)&ctx->st->module_mac_data,
            sizeof(ctx->st->module_mac_data));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
            KPEP_PROV_PARAM_LOG_FIPS_INDICATORS,
            (char **)&str_indicator,
            sizeof(str_indicator));            
    *p = OSSL_PARAM_construct_end();

    if (!c_get_params(ctx->handle, core_params)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }

    // Check for flag to log FIPS indicators
    if (str_indicator && !strncmp(str_indicator, "1", 1)) {
        OSSL_INDICATOR_set_callback((OSSL_LIB_CTX *)c_get_libctx(ctx->handle), fips_indicator_cb);
    }

    return 1;
}

/* *** APP-FACING (parameters we provide to the core/app) ****************************************/

static const OSSL_PARAM kpep_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_DEFN(KPEP_PROV_PARAM_RESTRICTED_MODE, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_DEFN(KPEP_PROV_PARAM_SEED_SOURCES, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *kpep_gettable_params(void *provctx)
{
    return kpep_param_types;
}

static int kpep_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    //KPEP_PROVIDER_CTX *ctx = (KPEP_PROVIDER_CTX*)provctx;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, KPEP_PROVIDER_MODULE_NAME))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, KPEP_PROVIDER_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, KPEP_PROVIDER_BUILDINFO_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
        return 0;
    p = OSSL_PARAM_locate(params, KPEP_PROV_PARAM_RESTRICTED_MODE);
    if (p != NULL && !OSSL_PARAM_set_int(p, kpep_seeding_get_restricted_mode()))
        return 0;
    p = OSSL_PARAM_locate(params, KPEP_PROV_PARAM_SEED_SOURCES);
    if (p != NULL) {
        const char *desc = kpep_seeding_get_description();
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

extern const OSSL_DISPATCH kpep_seeding_functions[];

static int kpep_random_bytes(void *vprov, int which,
                             void *buf, size_t n, unsigned int strength) 
{
    KPEP_PROVIDER_CTX *prov_ctx = (KPEP_PROVIDER_CTX *)vprov;
    const OSSL_DISPATCH *disp = kpep_seeding_functions;
    static OSSL_FUNC_rand_generate_fn *generate_fn = NULL;

    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: %s\n", MODULE_NAME, __func__);
    #endif

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

/* ************************************************************************************************
 * ************************************************************************************************
 * SELF-TEST INFRASTRUCTURE
 * ************************************************************************************************
 * ***********************************************************************************************/

static void set_self_test_cb(KPEP_PROVIDER_CTX *ctx)
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

static int kpep_self_test(void *provctx)
{
    KPEP_PROVIDER_CTX *ctx = (KPEP_PROVIDER_CTX*)provctx;
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
#define KPEP_NAMES_HMAC      "HMAC"
#define KPEP_NAMES_SHA2_256  "SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1"
#define KPEP_NAMES_SHA3_256  "SHA3-256:2.16.840.1.101.3.4.2.8"
#define KPEP_NAMES_SEED      "KPEP-SEED"
//#define KPEP_NAMES_CORE      "CORE-SEED"
#define DEFAULT_NAMES_SEED   "SEED-SRC"  // This is hardcoded and not in "names.h"

EXPORT_VISIBILITY_HIDDEN
extern const OSSL_DISPATCH kpep_sha2_digest_functions[];
EXPORT_VISIBILITY_HIDDEN
extern const OSSL_DISPATCH kpep_sha3_digest_functions[];
EXPORT_VISIBILITY_HIDDEN
extern const OSSL_DISPATCH kpep_hmac_functions[];
EXPORT_VISIBILITY_HIDDEN
extern const OSSL_DISPATCH kpep_seeding_functions[];
//EXPORT_VISIBILITY_HIDDEN
//extern const OSSL_DISPATCH kpep_core_seed_functions[];

static const OSSL_ALGORITHM kpep_rands[] = {
    { DEFAULT_NAMES_SEED, KPEP_MODULE_PROPERTIES, kpep_seeding_functions, NULL }, // OpenSSL default seed name
    { KPEP_NAMES_SEED, KPEP_MODULE_PROPERTIES, kpep_seeding_functions, NULL },
//    { KPEP_NAMES_CORE, KPEP_INTEROP_PROPERTIES, kpep_core_seed_functions, NULL },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM kpep_digests[] = {
    { KPEP_NAMES_SHA2_256, KPEP_MODULE_PROPERTIES, kpep_sha2_digest_functions, NULL },
    { KPEP_NAMES_SHA3_256, KPEP_MODULE_PROPERTIES, kpep_sha3_digest_functions, NULL },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM kpep_macs[] = {
    { KPEP_NAMES_HMAC, KPEP_MODULE_PROPERTIES, kpep_hmac_functions, NULL },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *kpep_query(void *provctx, int operation_id, int *no_cache)
{
    KPEP_PROVIDER_CTX *ctx = (KPEP_PROVIDER_CTX*) provctx;
    *no_cache = 1;  // Do NOT cache the algorithms

    if (!ossl_prov_is_running())
        return NULL;

    switch (operation_id) {
    case OSSL_OP_RAND:
        return kpep_rands;
#ifdef FIPS_ACVP
    case OSSL_OP_DIGEST:
        return kpep_digests;
    case OSSL_OP_MAC:
        return kpep_macs;
#else
    case OSSL_OP_DIGEST:
        return OSSL_PROVIDER_available(ctx->libctx, "kpfp")?NULL:kpep_digests;
    case OSSL_OP_MAC:
        return OSSL_PROVIDER_available(ctx->libctx, "kpfp")?NULL:kpep_macs;
#endif
    }
   return NULL;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * PROVIDER FUNCTIONS -- INIT, DISPATCH, TEARDOWN, ETC
 * ************************************************************************************************
 * ***********************************************************************************************/

static KPEP_PROVIDER_CTX *kpep_ctx_new(OSSL_LIB_CTX *libctx, 
                                          const OSSL_CORE_HANDLE *handle, 
                                          BIO_METHOD *bm) 
{
    KPEP_PROVIDER_CTX *ctx;

    ctx = (KPEP_PROVIDER_CTX*) kpep_zalloc(sizeof(KPEP_PROVIDER_CTX));
    if (!ctx)
        return NULL;

    /* Self-Test params */
    ctx->st = (SELF_TEST_PARAMS*) kpep_zalloc(sizeof(SELF_TEST_PARAMS));
    if (!ctx->st) {
        kpep_free(ctx);
        return NULL;
    }
    ctx->st->libctx = libctx;

    /* Global handles */
    ctx->handle = handle;
    ctx->libctx = libctx;
    ctx->corebiometh = bm;

    return ctx;
}

static void kpep_ctx_free(KPEP_PROVIDER_CTX *ctx) 
{
    if (!ctx) 
        return;
    
    OPENSSL_clear_free(ctx->st, sizeof(SELF_TEST_PARAMS));
    OPENSSL_clear_free(ctx, sizeof(KPEP_PROVIDER_CTX));
    kpep_log(LOG_LVL_INFO, MODULE_NAME, "Provider teardown complete");
}

static void kpep_teardown(void *provctx)
{
    KPEP_PROVIDER_CTX *ctx = (KPEP_PROVIDER_CTX*)provctx;

    kpep_seeding_fini();
	kpep_logging_fini();
    if (ctx->libctx) {
        OSSL_LIB_CTX_free(ctx->libctx);
        ctx->libctx = NULL;
    }
    kpep_ctx_free((KPEP_PROVIDER_CTX*)provctx);
}

/* Functions we provide to the core */
static const OSSL_DISPATCH kpep_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN,         (void (*)(void))kpep_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,  (void (*)(void))kpep_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,       (void (*)(void))kpep_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,  (void (*)(void))kpep_query },
    { OSSL_FUNC_PROVIDER_SELF_TEST,        (void (*)(void))kpep_self_test },
    { OSSL_FUNC_PROVIDER_RANDOM_BYTES,     (void (*)(void))kpep_random_bytes },
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
    KPEP_RESULT rv = KPEP_R_SUCCESS;

    KPEP_PROVIDER_CTX *newctx = NULL;
    BIO_METHOD *corebiometh;
    OSSL_LIB_CTX *libctx = NULL;
    int result = 0;

    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: Provider Init Start\n", MODULE_NAME);
    #endif

    // Load our error strings into OpenSSL
    rv = kpep_set_openssl_reason_strings();  // Init with OpenSSL
    if (rv) {
        ERR_raise(ERR_LIB_PROV, PROV_R_VALUE_ERROR);
    }

    // Output a log message about startup, if the config calls for logging (peek at config)
    if (OSSL_PROVIDER_conf_get_bool((void*)handle, KPEP_PROV_PARAM_LOG_SYSLOG_ACTIVATE, 0)) {
        syslog(LOG_LVL_INFO, MODULE_NAME": Provider startup initialized\n");
    }
    if (OSSL_PROVIDER_conf_get_bool((void*)handle, KPEP_PROV_PARAM_LOG_STDERR_ACTIVATE, 0)) {
        fprintf(stderr, "%s", MODULE_NAME": Provider startup initialized\n");
    }

    /* Pull core functions reated to BIO (at bottom of file) */
    if (!kpep_bio_from_dispatch(in))
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
    if ( ((corebiometh = kpep_bio_prov_init_bio_method()) == NULL) ||
         ((libctx = OSSL_LIB_CTX_new_child(handle, orig_in)) == NULL) ||
         ((newctx = kpep_ctx_new(libctx, handle, corebiometh)) == NULL ) ) { 
        kpep_log(LOG_LVL_ERR, MODULE_NAME, "Error creating new provider context\n");
    	goto err;
    }

    // Load our configuration from the core
    if (!kpep_get_params_from_core(newctx)) {
        // Error already raised
        goto err;
    }

    // Crypto algorithm Self-Tests
    if (!SELF_TEST_post(newctx->st, 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_POST_FAILURE);
        goto err; 
    }

    // Initialize all subsystems
    rv = kpep_logging_init(newctx);
    if (rv) {
        ERR_raise(ERR_LIB_, rv);
        goto err;
    }
    rv = kpep_seeding_init(newctx);
    if (rv) {
        ERR_raise(ERR_LIB_, rv);
        goto err;
    }

    // Signal success
    *out = kpep_dispatch_table;
    *provctx = newctx;
    result = 1;

err:
    if (!result) {
        kpep_teardown(newctx);
        *provctx = NULL;
    }

    kpep_log(LOG_LVL_INFO, MODULE_NAME, "Provider startup complete (%s)", result?"PASS":"FAIL");

ret:
    #if defined (KPEP_TRACE_SEED)
    printf("*** %s: Provider Init Complete\n", MODULE_NAME);
    #endif

    return result;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * BIO Infrastructure
 * ************************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
int kpep_bio_from_dispatch(const OSSL_DISPATCH *fns)
{
    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_BIO_NEW_FILE:
            if (c_bio_new_file == NULL)
                c_bio_new_file = OSSL_FUNC_BIO_new_file(fns);
            break;
        case OSSL_FUNC_BIO_NEW_MEMBUF:
            if (c_bio_new_membuf == NULL)
                c_bio_new_membuf = OSSL_FUNC_BIO_new_membuf(fns);
            break;
        case OSSL_FUNC_BIO_READ_EX:
            if (c_bio_read_ex == NULL)
                c_bio_read_ex = OSSL_FUNC_BIO_read_ex(fns);
            break;
        case OSSL_FUNC_BIO_WRITE_EX:
            if (c_bio_write_ex == NULL)
                c_bio_write_ex = OSSL_FUNC_BIO_write_ex(fns);
            break;
        case OSSL_FUNC_BIO_GETS:
            if (c_bio_gets == NULL)
                c_bio_gets = OSSL_FUNC_BIO_gets(fns);
            break;
        case OSSL_FUNC_BIO_PUTS:
            if (c_bio_puts == NULL)
                c_bio_puts = OSSL_FUNC_BIO_puts(fns);
            break;
        case OSSL_FUNC_BIO_CTRL:
            if (c_bio_ctrl == NULL)
                c_bio_ctrl = OSSL_FUNC_BIO_ctrl(fns);
            break;
        case OSSL_FUNC_BIO_UP_REF:
            if (c_bio_up_ref == NULL)
                c_bio_up_ref = OSSL_FUNC_BIO_up_ref(fns);
            break;
        case OSSL_FUNC_BIO_FREE:
            if (c_bio_free == NULL)
                c_bio_free = OSSL_FUNC_BIO_free(fns);
            break;
        case OSSL_FUNC_BIO_VPRINTF:
            if (c_bio_vprintf == NULL)
                c_bio_vprintf = OSSL_FUNC_BIO_vprintf(fns);
            break;
        }
    }
    return 1;
}

EXPORT_VISIBILITY_HIDDEN
OSSL_CORE_BIO *kpep_bio_new_file(const char *filename, const char *mode)
{
    if (c_bio_new_file == NULL)
        return NULL;
    return c_bio_new_file(filename, mode);
}

EXPORT_VISIBILITY_HIDDEN
OSSL_CORE_BIO *kpep_bio_new_membuf(const char *filename, int len)
{
    if (c_bio_new_membuf == NULL)
        return NULL;
    return c_bio_new_membuf(filename, len);
}

EXPORT_VISIBILITY_HIDDEN
int kpep_bio_read_ex(OSSL_CORE_BIO *bio, void *data, size_t data_len,
                          size_t *bytes_read)
{
    if (c_bio_read_ex == NULL)
        return 0;
    return c_bio_read_ex(bio, data, data_len, bytes_read);
}

EXPORT_VISIBILITY_HIDDEN
int kpep_bio_write_ex(OSSL_CORE_BIO *bio, const void *data, size_t data_len,
                           size_t *written)
{
    if (c_bio_write_ex == NULL)
        return 0;
    return c_bio_write_ex(bio, data, data_len, written);
}

EXPORT_VISIBILITY_HIDDEN
int kpep_bio_gets(OSSL_CORE_BIO *bio, char *buf, int size)
{
    if (c_bio_gets == NULL)
        return -1;
    return c_bio_gets(bio, buf, size);
}

EXPORT_VISIBILITY_HIDDEN
int kpep_bio_puts(OSSL_CORE_BIO *bio, const char *str)
{
    if (c_bio_puts == NULL)
        return -1;
    return c_bio_puts(bio, str);
}

EXPORT_VISIBILITY_HIDDEN
int kpep_bio_ctrl(OSSL_CORE_BIO *bio, int cmd, long num, void *ptr)
{
    if (c_bio_ctrl == NULL)
        return -1;
    return c_bio_ctrl(bio, cmd, num, ptr);
}

EXPORT_VISIBILITY_HIDDEN
int kpep_bio_up_ref(OSSL_CORE_BIO *bio)
{
    if (c_bio_up_ref == NULL)
        return 0;
    return c_bio_up_ref(bio);
}

EXPORT_VISIBILITY_HIDDEN
int kpep_bio_free(OSSL_CORE_BIO *bio)
{
    if (c_bio_free == NULL)
        return 0;
    return c_bio_free(bio);
}

EXPORT_VISIBILITY_HIDDEN
int kpep_bio_vprintf(OSSL_CORE_BIO *bio, const char *format, va_list ap)
{
    if (c_bio_vprintf == NULL)
        return -1;
    return c_bio_vprintf(bio, format, ap);
}

EXPORT_VISIBILITY_HIDDEN
int kpep_bio_printf(OSSL_CORE_BIO *bio, const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = kpep_bio_vprintf(bio, format, ap);
    va_end(ap);

    return ret;
}

static int bio_core_read_ex(BIO *bio, char *data, size_t data_len,
                            size_t *bytes_read)
{
    return kpep_bio_read_ex(BIO_get_data(bio), data, data_len, bytes_read);
}

static int bio_core_write_ex(BIO *bio, const char *data, size_t data_len,
                             size_t *written)
{
    return kpep_bio_write_ex(BIO_get_data(bio), data, data_len, written);
}

static long bio_core_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    return kpep_bio_ctrl(BIO_get_data(bio), cmd, num, ptr);
}

static int bio_core_gets(BIO *bio, char *buf, int size)
{
    return kpep_bio_gets(BIO_get_data(bio), buf, size);
}

static int bio_core_puts(BIO *bio, const char *str)
{
    return kpep_bio_puts(BIO_get_data(bio), str);
}

static int bio_core_new(BIO *bio)
{
    BIO_set_init(bio, 1);

    return 1;
}

static int bio_core_free(BIO *bio)
{
    BIO_set_init(bio, 0);
    kpep_bio_free(BIO_get_data(bio));

    return 1;
}

EXPORT_VISIBILITY_HIDDEN
BIO_METHOD *kpep_bio_prov_init_bio_method(void)
{
    BIO_METHOD *corebiometh = NULL;

    corebiometh = BIO_meth_new(BIO_TYPE_CORE_TO_PROV, "BIO to Core filter");
    if (corebiometh == NULL
            || !BIO_meth_set_write_ex(corebiometh, bio_core_write_ex)
            || !BIO_meth_set_read_ex(corebiometh, bio_core_read_ex)
            || !BIO_meth_set_puts(corebiometh, bio_core_puts)
            || !BIO_meth_set_gets(corebiometh, bio_core_gets)
            || !BIO_meth_set_ctrl(corebiometh, bio_core_ctrl)
            || !BIO_meth_set_create(corebiometh, bio_core_new)
            || !BIO_meth_set_destroy(corebiometh, bio_core_free)) {
        BIO_meth_free(corebiometh);
        return NULL;
    }

    return corebiometh;
}

EXPORT_VISIBILITY_HIDDEN
BIO *kpep_bio_new_from_core_bio(void *provctx, OSSL_CORE_BIO *corebio)
{
    BIO *outbio;
    BIO_METHOD *corebiometh = ((KPEP_PROVIDER_CTX *) provctx)->corebiometh;

    if (corebiometh == NULL)
        return NULL;

    if ((outbio = BIO_new(corebiometh)) == NULL)
        return NULL;
    if (!kpep_bio_up_ref(corebio)) {
        BIO_free(outbio);
        return NULL;
    }
    BIO_set_data(outbio, corebio);
    return outbio;
}
