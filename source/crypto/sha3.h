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

#ifndef ARDENT_SHA3_H
#define ARDENT_SHA3_H

#include "ardent/ardent.h"
#include "openssl/params.h"

# ifdef __cplusplus
extern "C" {
# endif

typedef struct jent_sha_ctx SHA3_CTX;

SHA3_CTX* sha3_ctx_new(void);
void      sha3_ctx_free(SHA3_CTX* ctx);
int       sha3_init(SHA3_CTX* ctx, ossl_unused const OSSL_PARAM params[]);
int       sha3_update(SHA3_CTX* ctx, const unsigned char *msg, size_t msg_len);
int       sha3_final(SHA3_CTX* ctx, unsigned char *digest, size_t *digest_len);
int       sha3_oneshot(const unsigned char *message, unsigned int len, unsigned char *digest);

const OSSL_PARAM *sha3_gettable_params(void *provctx);
int sha3_get_params(OSSL_PARAM params[]);

# ifdef __cplusplus
}
# endif
#endif /* ARDENT_SHA3_H */

