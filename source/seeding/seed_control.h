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

#ifndef ARDENT_SEED_CONTROL_H
#define ARDENT_SEED_CONTROL_H
#pragma once

#include "ardent/ardent.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ************************************************************************************************
 * SEED Control / Management (called internally by ardent_seeding.c)
 * ***********************************************************************************************/

/* Opaque context structure for Seed Control */
typedef struct seed_control_ctx_st SEED_CONTROL_CTX;

/* Allocate and return an opaque contaxt structure */
SEED_CONTROL_CTX* seed_control_new(void* prov_ctx, ARDENT_RESULT* errnum);
/* Free the opaque context structure */
void              seed_control_free(SEED_CONTROL_CTX* ctx);
/* Get the current state of the seed control (see ardent_seeding.h for return values) */
uint32_t          seed_control_get_state(SEED_CONTROL_CTX* ctx);
/* 
 * Get a "pretty" string description of each loaded sink, one-per-line;   
 * Write to the provided buffer of length 1024 
 */
void              seed_control_get_description(SEED_CONTROL_CTX* ctx, char* buffer);
/*
 * Get whether the current entropy counting method is restrictive (Method #1)
 */
int               seed_control_get_restricted_mode(SEED_CONTROL_CTX* ctx);
/* 
 * Gather entropy and return nbits worth of entropy in an allocated array (user must free).  The 
 * length of the buffer 'out' is returned in 'out_len', and *can be arbitrarily long*, perhaps 
 * 10s of thousands of bits.
 */
ARDENT_RESULT       seed_control_gather(SEED_CONTROL_CTX* ctx, 
                                      uint8_t** out, size_t* out_len, 
                                      size_t nbits, int validated);

#ifdef __cplusplus
}
#endif
#endif /* ARDENT_SEED_CONTROL_H */
