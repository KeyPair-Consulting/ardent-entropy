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

#ifndef KPEP_DRBG_H
#define KPEP_DRBG_H
# pragma once

#include <stdlib.h>
#include <stdint.h>
#include "kpep/kpep_error.h"

# ifdef __cplusplus
extern "C" {
# endif

typedef enum {
    ENTROPY_MODE_RBG3 = 0,
    ENTROPY_MODE_RBG2
} RBG_ENTROPY_MODE;

#define DRBG_MAX_BYTES_PER_REQUEST (8192)   // 65536 bits
#define RBG2_RESEED_MAX_BITS       (1<<17)  // By standard
#define RBG2_RESEED_MAX_BYTES      (RBG2_RESEED_MAX_BITS>>3)

// Max lengths of various inputs (1MB for most)
#define MAX_ENTROPY_LEN  (1024*1024)
#define MAX_NONCE_LEN    (1024*1024)
#define MAX_ADDL_LEN     (1024*1024)
#define MAX_PERS_LEN      1024

// Opaque context structure
typedef struct kpep_drbg_ctx_st KPEP_DRBG_CTX;

// Callable functions for DRBG management
void* drbg_new (void* seed_ctx, uint32_t entropy_mode, KPEP_RESULT *errnum);
void  drbg_free(KPEP_DRBG_CTX* ctx);
int   drbg_verify_zeroization(KPEP_DRBG_CTX* ctx);

// Callable functions for DRBG operations
KPEP_RESULT drbg_instantiate   (KPEP_DRBG_CTX* ctx, int strength,
								const uint8_t* perso, uint32_t perso_len);
void        drbg_uninstantiate (KPEP_DRBG_CTX* ctx);
KPEP_RESULT drbg_generate      (KPEP_DRBG_CTX* ctx, 
								uint8_t *rand, uint32_t rand_len);

#ifdef __cplusplus
}
#endif
#endif /* KPEP_DRBG */

