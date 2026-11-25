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

#ifndef ARDENT_SHA2_H
#define ARDENT_SHA2_H

#define SHA2_256_DIGEST_SIZE ( 256 / 8)
#define SHA2_256_BLOCK_SIZE  ( 512 / 8)

#include "openssl/params.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sha2_ctx_st SHA2_CTX;

SHA2_CTX* sha2_ctx_new(void);
void      sha2_ctx_free(SHA2_CTX* ctx);
void*     sha2_ctx_dup(void* ctx);
int       sha2_init(SHA2_CTX* ctx, const OSSL_PARAM params[]);
int       sha2_update(SHA2_CTX* ctx, const unsigned char *msg, size_t msg_len);
int       sha2_final(SHA2_CTX* ctx, unsigned char *digest, size_t *digest_len);
int       sha2_oneshot(const unsigned char *message, unsigned int len, unsigned char *digest);

const OSSL_PARAM *sha2_gettable_params(void *provctx);
int sha2_get_params(OSSL_PARAM params[]);

#ifdef __cplusplus
}
#endif

#endif /* ARDENT_SHA2_H */

