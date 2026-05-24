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

#ifndef KPEP_HMAC_H
#define KPEP_HMAC_H

#include "kpep/kpep.h"

# ifdef __cplusplus
extern "C" {
# endif

typedef struct hmac_ctx_st HMAC_CTX;

HMAC_CTX*       hmac_ctx_new(void);
void            hmac_ctx_free(HMAC_CTX* ctx);

int  hmac_init (HMAC_CTX *ctx, 
                const unsigned char *key,
                unsigned int key_size,
                void* params);  // ossl_unused const OSSL_PARAM params[]);

void hmac_reinit(HMAC_CTX *ctx);

int  hmac_update(HMAC_CTX *ctx, 
                const unsigned char *message,
                unsigned int message_len);

int  hmac_final(HMAC_CTX *ctx, 
                unsigned char *mac,
                size_t *mac_len,
                unsigned int mac_size);

int  hmac      (const unsigned char *key, 
                unsigned int key_size,
                const unsigned char *message, 
                unsigned int message_len,
                unsigned char *mac, 
                unsigned int mac_size);

# ifdef __cplusplus
}
# endif
#endif /* KPEP_HMAC_H */

