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
#include "openssl/core_names.h"
#include "openssl/core_dispatch.h"    /* OSSL Functions */

#include "../jitterentropy/jitterentropy-sha3.h"
#include "sha3.h"

/* ************************************************************************************************
 * ************************************************************************************************
 * JEnt SHA3-256 facade/wrapper functions
 * ************************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
SHA3_CTX* sha3_ctx_new(void)
{
    SHA3_CTX *newctx = NULL;
    jent_sha3_alloc((void**)&newctx);  // Guaranteed NO CHANGE to ptr if alloc failure
    return newctx;
}

EXPORT_VISIBILITY_HIDDEN
void sha3_ctx_free(SHA3_CTX* ctx)
{
    jent_sha3_dealloc(ctx);
}

EXPORT_VISIBILITY_HIDDEN
void* sha3_ctx_dup(void* ctx)
{
    SHA3_CTX *newctx = NULL;
    if (!ctx)
        return NULL;
    newctx = sha3_ctx_new();
    if (newctx)
        memcpy(newctx, ctx, sizeof(SHA3_CTX));
    return newctx;
}

EXPORT_VISIBILITY_HIDDEN
int sha3_init(SHA3_CTX* ctx, ossl_unused const OSSL_PARAM params[])
{
    if (!ctx)
        return 0;
    jent_sha3_256_init(ctx);
    return 1;
}

EXPORT_VISIBILITY_HIDDEN
int sha3_update(SHA3_CTX* ctx, const unsigned char *msg, size_t msg_len)
{
    if (!ctx)
        return 0;    
    jent_sha3_update(ctx, msg, msg_len);
    return 1;
}

EXPORT_VISIBILITY_HIDDEN
int sha3_final(SHA3_CTX* ctx, unsigned char *digest, size_t *digest_len)
{
    if (!ctx || !digest)
        return 0;
    jent_sha3_final(ctx, digest);
    if (digest_len)
        *digest_len = JENT_SHA3_256_SIZE_DIGEST;
    return 1;
}

EXPORT_VISIBILITY_HIDDEN
int sha3_oneshot(const unsigned char *message, unsigned int len, unsigned char *digest)
{
    SHA3_CTX ctx;

    if (!digest)
        return 0;
    jent_sha3_256_init(&ctx);
    jent_sha3_update(&ctx, message, len);
    jent_sha3_final(&ctx, digest);
    return 1;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * JEnt SHA3-256 parameter functions
 * ************************************************************************************************
 * ***********************************************************************************************/

static const OSSL_PARAM kpep_sha3_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, NULL),
    OSSL_PARAM_END
};

EXPORT_VISIBILITY_HIDDEN
const OSSL_PARAM *sha3_gettable_params(void *provctx)
{
    return kpep_sha3_known_gettable_params;
}

EXPORT_VISIBILITY_HIDDEN
int sha3_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, JENT_SHA3_256_SIZE_BLOCK)) {
        kpep_log(LOG_LVL_ERR, "SHA3", "Failed to set parameter 'blocksize'");
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, JENT_SHA3_256_SIZE_DIGEST)) {
        kpep_log(LOG_LVL_ERR, "SHA3", "Failed to set parameter 'size'");
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, 0)) {
        kpep_log(LOG_LVL_ERR, "SHA3", "Failed to set parameter 'xof'");
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, 0)) {
        kpep_log(LOG_LVL_ERR, "SHA3", "Failed to set parameter 'algid-absent'");
        return 0;
    }
    return 1;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * Algorithm Implementation Interface
 * ************************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
const OSSL_DISPATCH kpep_sha3_digest_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,          (void (*)(void))sha3_ctx_new },
    { OSSL_FUNC_DIGEST_FREECTX,         (void (*)(void))sha3_ctx_free },
    { OSSL_FUNC_DIGEST_DUPCTX,          (void (*)(void))sha3_ctx_dup },
    { OSSL_FUNC_DIGEST_INIT,            (void (*)(void))sha3_init },
    { OSSL_FUNC_DIGEST_UPDATE,          (void (*)(void))sha3_update },
    { OSSL_FUNC_DIGEST_FINAL,           (void (*)(void))sha3_final },
    { OSSL_FUNC_DIGEST_GET_PARAMS,      (void (*)(void))sha3_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))sha3_gettable_params },
    OSSL_DISPATCH_END
};
