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

#ifndef ARDENT_SELF_TEST_H
#define ARDENT_SELF_TEST_H
#pragma once

//#include "openssl/core_dispatch.h"
#include "openssl/types.h"
#include "openssl/self_test.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ************************************************************************************************
 * GENERAL/USEFUL UTILITIES
 * ***********************************************************************************************/

typedef struct self_test_post_params_st {
    OSSL_LIB_CTX *libctx;

    /* Module integrity check parameters */
    const char       *module_filename;    /* Module file to perform MAC on */
    const char       *module_mac_data;    /* Expected module MAC integrity */

    /* Callback for Self-Test reporting and testing */
    OSSL_CALLBACK *cb;
    void *cb_arg;

} SELF_TEST_PARAMS;

/* Perform built-in self-tests; 0==FAIL/1==PASS */
int SELF_TEST_post(SELF_TEST_PARAMS *st, int on_demand_test);

/* Convenience function to test provider run state */
int ossl_prov_is_running(void);

/* Convenience function to set OpenSSL into an error state */
void ossl_set_error_state(const char *type);

#ifdef __cplusplus
}
#endif
#endif /* ARDENT_SELF_TEST_H */