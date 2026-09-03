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

#include <string.h>
#include "openssl/evp.h"
#include "openssl/params.h"
#include "openssl/crypto.h"
#include "internal/cryptlib.h"
#include "openssl/err.h"
#include "openssl/proverr.h"
#include "internal/tsan_assist.h"

#include "kpep_internal.h"
#include "integrity.h"
#include "kpep_self_test.h"
#include "crypto/sha3.h"
#include "crypto/hmac.h"
#include "crypto/drbg_acvp.h"

#define MODULE_NAME "SELF-TEST"

/* DEBUGGING: Extra Output for various data */
//#define DEBUG_HMAC_CAST
//#define DEBUG_MODULE_MAC
//#define DEBUG_INTEGRITY

/* ************************************************************************************************
 * ************************************************************************************************
 * FIPS Requirements
 * ************************************************************************************************
 * ***********************************************************************************************/

#define ALLOW_RUN_ONCE_IN_FIPS
#include "internal/thread_once.h"

#define FIPS_STATE_INIT     0
#define FIPS_STATE_SELFTEST 1
#define FIPS_STATE_RUNNING  2
#define FIPS_STATE_ERROR    3

/*
 * The number of times the module will report it is in the error state
 * before going quiet.
 */
#define FIPS_ERROR_REPORTING_RATE_LIMIT     10

static CRYPTO_RWLOCK *self_test_lock = NULL;

static CRYPTO_ONCE fips_self_test_init = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(do_fips_self_test_init)
{
    /*
     * These locks get freed in platform specific ways that may occur after we
     * do mem leak checking. If we don't know how to free it for a particular
     * platform then we just leak it deliberately.
     */
    self_test_lock = CRYPTO_THREAD_lock_new();
    return self_test_lock != NULL;
}

/*
 * Declarations for the DEP entry/exit points.
 * Ones not required or incorrect need to be undefined or redefined respectively.
 */
#define DEP_INITIAL_STATE   FIPS_STATE_INIT
#define DEP_INIT_ATTRIBUTE  static
#define DEP_FINI_ATTRIBUTE  static

static void init(void);
static void cleanup(void);

/*
 * This is the Default Entry Point (DEP) code.
 * See FIPS 140-2 IG 9.10
 */
#if defined(_WIN32) || defined(__CYGWIN__)
# ifdef __CYGWIN__
/* pick DLL_[PROCESS|THREAD]_[ATTACH|DETACH] definitions */
#  include <windows.h>
/*
 * this has side-effect of _WIN32 getting defined, which otherwise is
 * mutually exclusive with __CYGWIN__...
 */
# endif

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        init();
        break;
    case DLL_PROCESS_DETACH:
        cleanup();
        break;
    default:
        break;
    }
    return TRUE;
}

#elif defined(__GNUC__) && !defined(_AIX)
# undef DEP_INIT_ATTRIBUTE
# undef DEP_FINI_ATTRIBUTE
# define DEP_INIT_ATTRIBUTE static __attribute__((constructor))
# define DEP_FINI_ATTRIBUTE static __attribute__((destructor))

#elif defined(__sun)
# pragma init(init)
# pragma fini(cleanup)

#elif defined(_AIX) && !defined(__GNUC__)
void _init(void);
void _cleanup(void);
# pragma init(_init)
# pragma fini(_cleanup)
void _init(void)
{
    init();
}
void _cleanup(void)
{
    cleanup();
}

#elif defined(__hpux)
# pragma init "init"
# pragma fini "cleanup"

#elif defined(__TANDEM)
/* Method automatically called by the NonStop OS when the DLL loads */
void __INIT__init(void) {
    init();
}

/* Method automatically called by the NonStop OS prior to unloading the DLL */
void __TERM__cleanup(void) {
    cleanup();
}

#else
/*
 * This build does not support any kind of DEP.
 * We force the self-tests to run as part of the FIPS provider initialisation
 * rather than being triggered by the DEP.
 */
# undef DEP_INIT_ATTRIBUTE
# undef DEP_FINI_ATTRIBUTE
# undef DEP_INITIAL_STATE
# define DEP_INITIAL_STATE  FIPS_STATE_SELFTEST
#endif

static TSAN_QUALIFIER int FIPS_state = DEP_INITIAL_STATE;

#if defined(DEP_INIT_ATTRIBUTE)
DEP_INIT_ATTRIBUTE void init(void)
{
    tsan_store(&FIPS_state, FIPS_STATE_SELFTEST);
}
#endif

#if defined(DEP_FINI_ATTRIBUTE)
DEP_FINI_ATTRIBUTE void cleanup(void)
{
    CRYPTO_THREAD_lock_free(self_test_lock);
}
#endif

/* ************************************************************************************************
 * ************************************************************************************************
 * DEBUG PRINT
 * ************************************************************************************************
 * ***********************************************************************************************/

#if defined(DEBUG_CAST) || defined (DEBUG_INTEGRITY)
static void debug_print_bytes(const char* label, const unsigned char *buf, int len, int newline) 
{
	int i;
	if (label)
		printf("%s : [%04d] ", label, len);
    for (i=0; i<len; ++i) {
        printf("%02X", buf[i]);
    }
	if (newline)
		printf("\n");
}
#endif

/* ************************************************************************************************
 * ************************************************************************************************
 * Cryptographic Algorithm Self Tests (CASTs)
 * ************************************************************************************************
 * ***********************************************************************************************/

#include "kpep_self_test.inc"   // Self-test data

/* ************************************************************************************************
 * HMAC-SHA2-256
 */

static
int hmac_cast(SELF_TEST_PARAMS *st, OSSL_SELF_TEST *ev) 
{
    int ok = 0;
    unsigned char mac[KPEP_GLOBAL_DIGEST_SIZE] = { 0 };

    OSSL_SELF_TEST_onbegin(ev, OSSL_SELF_TEST_TYPE_KAT_INTEGRITY, 
                               OSSL_SELF_TEST_DESC_INTEGRITY_HMAC);

    ok = hmac(kpep_integrity_key, kpep_integrity_key_len,
              kat_pt, sizeof(kat_pt),
              mac, KPEP_GLOBAL_DIGEST_SIZE);
    if (!ok) {
        kpep_log(LOG_LVL_FATAL, MODULE_NAME, "HMAC CAST failure (primitive)\n");
        ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_KAT_FAILURE);
        return 0;
    }

    /* Optional corruption */
    OSSL_SELF_TEST_oncorrupt_byte(ev, mac);

    ok = !memcmp(mac, hmac_kat_mac, KPEP_GLOBAL_DIGEST_SIZE); // Success on zero
    if (!ok) {
        kpep_log(LOG_LVL_FATAL, MODULE_NAME, "HMAC CAST failure (compare)");
        ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_KAT_FAILURE);
        #ifdef DEBUG_CAST
        debug_print_bytes("HMAC CAST CALC: ", mac, KPEP_GLOBAL_DIGEST_SIZE, 1);
        debug_print_bytes("HMAC CAST EXP : ", hmac_kat_mac, KPEP_GLOBAL_DIGEST_SIZE, 1);
        #endif
    }

    OSSL_SELF_TEST_onend(ev, ok);
    return ok;
}

/* ************************************************************************************************
 * SHA3-256
 */

static
int sha3_cast(SELF_TEST_PARAMS *st, OSSL_SELF_TEST *ev) 
{
    int ok = 0;
    unsigned char digest[KPEP_GLOBAL_DIGEST_SIZE] = { 0 };

    OSSL_SELF_TEST_onbegin(ev, OSSL_SELF_TEST_TYPE_KAT_DIGEST, 
                               OSSL_SELF_TEST_DESC_MD_SHA3);

    ok = sha3_oneshot(kat_pt, sizeof(kat_pt), digest);
    if (!ok) {
        kpep_log(LOG_LVL_FATAL, MODULE_NAME, "HASH CAST failure (primitive)\n");
        ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_KAT_FAILURE);
        return 0;
    }

    /* Optional corruption */
    OSSL_SELF_TEST_oncorrupt_byte(ev, digest);

    ok = !memcmp(digest, hash_kat_digest, KPEP_GLOBAL_DIGEST_SIZE); // Success on zero
    if (!ok) {
        kpep_log(LOG_LVL_FATAL, MODULE_NAME, "HASH CAST failure (compare)");
        ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_KAT_FAILURE);
        #ifdef DEBUG_CAST
        debug_print_bytes("HASH CAST CALC: ", digest, KPEP_GLOBAL_DIGEST_SIZE, 1);
        debug_print_bytes("HASH CAST EXP : ", hash_kat_digest, KPEP_GLOBAL_DIGEST_SIZE, 1);
        #endif
    }

    OSSL_SELF_TEST_onend(ev, ok);
    return ok;
}

/* ************************************************************************************************
 * HASH-DRBG (w/SHA2-256)
 */

static
int drbg_cast(SELF_TEST_PARAMS *st, OSSL_SELF_TEST *ev) 
{
    int ok = 0; // Assume failure
    uint8_t buffer[64] = { 0 };

    const uint32_t entropy_len = sizeof(drbg_inst_entropy);
    const uint32_t nonce_len   = sizeof(drbg_inst_nonce);
    const uint32_t pers_len    = sizeof(drbg_inst_pers);
    const uint32_t addl_len    = sizeof(drbg_gen1_addl);
    const uint32_t exp_len     = sizeof(drbg_expected);

    KPEP_DRBG_CTX* ctx = NULL;

    OSSL_SELF_TEST_onbegin(ev, OSSL_SELF_TEST_TYPE_DRBG, 
                               OSSL_SELF_TEST_DESC_DRBG_HASH);

    if ((ctx = drbg_new(NULL)) != NULL && 
        !drbg_instantiate_ex(ctx, 128, 
                            drbg_inst_entropy, entropy_len,
                            drbg_inst_nonce, nonce_len, 
                            drbg_inst_pers, pers_len) &&
        !drbg_generate_ex(ctx, buffer, exp_len,
                            drbg_gen1_entropy, entropy_len, 
                            drbg_gen1_addl, addl_len) &&
        !drbg_generate_ex(ctx, buffer, exp_len,
                            drbg_gen2_entropy, entropy_len, 
                            drbg_gen2_addl, addl_len)) {
        // Optional corruption
        OSSL_SELF_TEST_oncorrupt_byte(ev, buffer);
        // Check result
        ok = !memcmp(buffer, drbg_expected, exp_len);  // Success on zero
        if (!ok) {
            kpep_log(LOG_LVL_FATAL, MODULE_NAME, "DRBG CAST failure (compare)");
            ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_KAT_FAILURE);
            #ifdef DEBUG_CAST
            debug_print_bytes("DRBG CAST CALC: ", buffer, KPEP_GLOBAL_DIGEST_SIZE, 1);
            debug_print_bytes("DRBG CAST EXP : ", drbg_expected, KPEP_GLOBAL_DIGEST_SIZE, 1);
            #endif
        }
    }

    OSSL_SELF_TEST_onend(ev, ok);

	// Cleanup
    drbg_uninstantiate(ctx);
	drbg_free(ctx);
    return ok;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * HMAC Integrity Test
 * ************************************************************************************************
 * ***********************************************************************************************/

#define INTEGRITY_PAIR_DELIM_STRING "="
#define INTEGRITY_DATA_DELIM_STRING ":"
#define INTEGRITY_DATA_DELIM_CHAR   ':'

EXPORT_VISIBILITY_HIDDEN
int integrity_test(SELF_TEST_PARAMS *st, OSSL_SELF_TEST *ev) 
{
    int ok = 0;  // Default fail
    int rv;
    unsigned char mac[KPEP_GLOBAL_DIGEST_SIZE];
    unsigned char exp[KPEP_GLOBAL_DIGEST_SIZE];
    size_t mac_len = KPEP_GLOBAL_DIGEST_SIZE;
    size_t exp_len;

    OSSL_SELF_TEST_onbegin(ev, OSSL_SELF_TEST_TYPE_MODULE_INTEGRITY, 
                               OSSL_SELF_TEST_DESC_INTEGRITY_HMAC);

    // Validate arguments
    if (!st || !st->module_filename || !st->module_mac_data) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CONFIG_DATA);
        goto err_onend;        
    }

    #ifdef DEBUG_INTEGRITY
    printf("Module Filename: %s\n", st->module_filename);
    printf("Module Mac     : %s\n", st->module_mac_data);
    #endif

    // Load expected mac
    if (!OPENSSL_hexstr2buf_ex(exp, sizeof(exp), &exp_len, st->module_mac_data, INTEGRITY_DATA_DELIM_CHAR)) {
        kpep_log(LOG_LVL_ERR, MODULE_NAME, "Failed to convert expected MAC value for integrity test");
        goto err;
    }

    // Do the file HMAC, get the MAC
    if ((rv = integrity_check_file(st->module_filename, NULL, 0, mac, &mac_len)) != KPEP_R_SUCCESS) {
        kpep_log(LOG_LVL_ERR, MODULE_NAME, "Failed to perform the integrity test: %s", kpep_get_reason_string(rv));
        goto err;
    }

    /* Optional corruption */
    OSSL_SELF_TEST_oncorrupt_byte(ev, mac);

    // Check the calculated vs expected
    ok = (memcmp(mac, exp, KPEP_GLOBAL_DIGEST_SIZE) == 0);

err:
    if (!ok) {
        kpep_log(LOG_LVL_WARN, MODULE_NAME, "Integrity test failure (compare)");
        ERR_raise(ERR_LIB_PROV, PROV_R_MODULE_INTEGRITY_FAILURE);
        #ifdef DEBUG_INTEGRITY
        debug_print_bytes("INTEGRITY CALC: ", mac, KPEP_GLOBAL_DIGEST_SIZE, 1);
        debug_print_bytes("INTEGRITY EXP : ", exp, KPEP_GLOBAL_DIGEST_SIZE, 1);
        #endif
    }
    // Zeroize, as per AS05.10
    {
        volatile size_t i;
        for (i=0; i<sizeof(mac); ++i)
            mac[i] = 0x00;
    }
err_onend:
    OSSL_SELF_TEST_onend(ev, ok);
    return ok;
}


/* ************************************************************************************************
 * ************************************************************************************************
 * Power-On Self Tests (POSTs) and State management
 * ************************************************************************************************
 * ***********************************************************************************************/

static void set_fips_state(int state)
{
    tsan_store(&FIPS_state, state);
}

EXPORT_VISIBILITY_HIDDEN
void ossl_set_error_state(const char *type)
{
    int cond_test = (type != NULL && strcmp(type, OSSL_SELF_TEST_TYPE_PCT) == 0);

    if (cond_test) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FIPS_MODULE_CONDITIONAL_ERROR);
    } else {
        set_fips_state(FIPS_STATE_ERROR);
        ERR_raise(ERR_LIB_PROV, PROV_R_FIPS_MODULE_ENTERING_ERROR_STATE);
    }
}

EXPORT_VISIBILITY_HIDDEN
int ossl_prov_is_running(void)
{
    int res, loclstate;
    static TSAN_QUALIFIER unsigned int rate_limit = 0;

    loclstate = tsan_load(&FIPS_state);
    res = loclstate == FIPS_STATE_RUNNING || loclstate == FIPS_STATE_SELFTEST;
    if (loclstate == FIPS_STATE_ERROR)
        if (tsan_counter(&rate_limit) < FIPS_ERROR_REPORTING_RATE_LIMIT)
            ERR_raise(ERR_LIB_PROV, PROV_R_FIPS_MODULE_IN_ERROR_STATE);
    return res;
}

/* This API is triggered either on loading of the module or on demand */
EXPORT_VISIBILITY_HIDDEN
int SELF_TEST_post(SELF_TEST_PARAMS *st, int on_demand_test)
{
    KPEP_RESULT rv;
    OSSL_SELF_TEST *ev = NULL;
    int loclstate, ok = 0;

    if (kpep_trace_seed_enabled) {
        kpep_trace("KPEP-CAST", "START");
    }

    if (!RUN_ONCE(&fips_self_test_init, do_fips_self_test_init)) {
        goto err;
    }

    loclstate = tsan_load(&FIPS_state);

    if (loclstate == FIPS_STATE_RUNNING) {
        if (!on_demand_test) {
            ok = 1;
            goto err;
        }
    } else if (loclstate != FIPS_STATE_SELFTEST) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_STATE);
        goto err;
    }

    if (!CRYPTO_THREAD_write_lock(self_test_lock)) {
        goto err;
    }
    loclstate = tsan_load(&FIPS_state);
    if (loclstate == FIPS_STATE_RUNNING) {
        if (!on_demand_test) {
            CRYPTO_THREAD_unlock(self_test_lock);
            ok = 1;
            goto err;
        }
        set_fips_state(FIPS_STATE_SELFTEST);
    } else if (loclstate != FIPS_STATE_SELFTEST) {
        CRYPTO_THREAD_unlock(self_test_lock);
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_STATE);
        goto err;
    }

    // We have to allocate, so we have to guarantee free
    do {
        ev = OSSL_SELF_TEST_new(st->cb, st->cb_arg);
        if (ev == NULL)
            break;
    
        /* Run the required KAT and Integrity Test */
        if (!hmac_cast(st, ev) || !integrity_test(st, ev))
            break;

        /* Run CASTs and the Integrity Test */
        ok  = sha3_cast(st, ev);
        ok &= drbg_cast(st, ev);

    } while (0);

    OSSL_SELF_TEST_free(ev);

    if (ok) {
        set_fips_state(FIPS_STATE_RUNNING);
    }
    else {
        kpep_log(LOG_LVL_ERR, MODULE_NAME, "POST failure\n");
        ossl_set_error_state(OSSL_SELF_TEST_TYPE_NONE);
    }
    CRYPTO_THREAD_unlock(self_test_lock);

err:

    if (kpep_trace_seed_enabled) {
        kpep_trace("KPEP-CAST", "END");
    }

    return ok;
}