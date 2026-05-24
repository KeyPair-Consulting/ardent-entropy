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

#ifndef KPEP_SEEDING_H
#define KPEP_SEEDING_H
#pragma once

#include <stddef.h>
#include "kpep/kpep.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ************************************************************************************************
 * STATE DEFINITIONS (values copied from from "openssl/evp.h")
 * ***********************************************************************************************/

# define KPEP_RAND_STATE_UNINITIALISED    0
# define KPEP_RAND_STATE_READY            1
# define KPEP_RAND_STATE_ERROR            2

/* ************************************************************************************************
 * SEED Stubs
 * These is a low-level API for direct access to the seed sources, used by seed_control.c to 
 * service requests from kpep_seeding.c.  The function definitions and the container structure
 * are provided for authors to construct external seed sources.
 * ***********************************************************************************************/

/* Allocate and return an opaque context structure or NULL and error number set */
typedef void*       (*stub_new_fn)       (void* prov_ctx, uint8_t idx, KPEP_RESULT* errnum);
/* Free the opaque context structure */
typedef void        (*stub_free_fn)      (void* ctx);
/* Return the simple "pretty" name for the source (e.g. "jitter" or "vendor-jitter") */
typedef const char* (*stub_get_name_fn)  (void* ctx);
/* Get state of the source; return BOOL if OK;  return errornum in argument of NOT OK */
typedef uint32_t    (*stub_get_state_fn) (void* ctx);
/* 
 * Gather entropy and return nbits worth of entropy in the provided 'out' array. The Stub
 * calculates how much raw entropy to gather based on the request size.  In all cases, the
 * number of gatehred bytes (and thge length of the array to hold them) will be returned in 
 * 'out_len'.  If the 'out' ptr is not provided, no gather is performed.
 */
typedef KPEP_RESULT (*stub_gather_fn)  (void* ctx, unsigned char* out, size_t* out_len, size_t nbits);

typedef struct stub_functions_st {
    stub_new_fn        new_fn;
    stub_free_fn       free_fn;
    stub_gather_fn     gather_fn;
    stub_get_name_fn   get_name_fn;
    stub_get_state_fn  get_state_fn;
} STUB_FUNCTIONS;

#ifdef __cplusplus
}
#endif
#endif /* KPEP_SEEDING_H */