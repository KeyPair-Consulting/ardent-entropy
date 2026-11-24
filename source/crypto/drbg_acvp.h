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
/*
 * This file not used internally, but is created and maintained for use in ACVP testing. The "_ex" 
 * functions are only exported when ARDent is compiled with the "FIPS_ACVP" preprocessor definition. 
 * They allow the entropy to be directly supplied to as required by testing.  This file 
 * intentionally uses the save exclusive name as kpep_drbg.h to ensure they are not both used.
 */

#ifdef KPEP_DRBG_H
#error "This file must be included *instead* of drbg.h; All defs needed for ACVP are here"
#else
#define KPEP_DRBG_H
# pragma once

#include <stdlib.h>
#include <stdint.h>
#include "drbg.h"  // Req'd functions and declarations for DRBG context management

# ifdef __cplusplus
extern "C" {
# endif

typedef uint32_t KPEP_RESULT;

// Opaque context structure
typedef struct kpep_drbg_ctx_st KPEP_DRBG_CTX;

void* drbg_new (void* seed_ctx, uint32_t entropy_mode, KPEP_RESULT *errnum);
void  drbg_free(KPEP_DRBG_CTX* ctx);
int   drbg_verify_zeroization(KPEP_DRBG_CTX* ctx);

// Callable functions for DRBG operations
void        drbg_uninstantiate (KPEP_DRBG_CTX* ctx);

// Low-level DRBG functions for ACVP testing
KPEP_RESULT drbg_instantiate_ex (KPEP_DRBG_CTX* ctx, int strength,
								 const uint8_t* entropy, uint32_t entropy_len, 
                                 const uint8_t* nonce, uint32_t nonce_len, 
                                 const uint8_t* pers, uint32_t pers_len);
KPEP_RESULT drbg_generate_ex    (KPEP_DRBG_CTX* ctx, 
	                             uint8_t *rand, uint32_t rand_len, 
								 const uint8_t *entropy, size_t entropy_len,
								 const uint8_t *addl, uint32_t addl_len);


#ifdef __cplusplus
}
#endif
#endif /* KPEP_DRBG_H */

