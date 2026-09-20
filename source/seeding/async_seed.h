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

#ifndef KPEP_ASYNC_SEED_H
#define KPEP_ASYNC_SEED_H
#pragma once

#include "kpep/kpep.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    WORKER_UNINITIALIZED = 0,
    WORKER_INITIALIZED,
    WORKER_RUNNING,
    WORKER_STOPPING,
    WORKER_STOPPED,
    WORKER_ERROR
} ASYNC_WORKER_STATE;

typedef struct async_ctx_st ASYNC_CTX;

EXPORT_VISIBILITY_HIDDEN
ASYNC_CTX* async_seed_new(void* prov_ctx, 
                          const STUB_FUNCTIONS* stub_fn, 
                          uint32_t ring_sz, 
                          uint8_t idx, 
                          uint32_t async_mode,
                          KPEP_RESULT *errnum);

EXPORT_VISIBILITY_HIDDEN
void async_seed_free(ASYNC_CTX *async_ctx);

EXPORT_VISIBILITY_HIDDEN
KPEP_RESULT async_seed_gather(ASYNC_CTX *async_ctx, 
                              unsigned char *out, 
                              size_t *out_len, 
                              size_t nbits);

EXPORT_VISIBILITY_HIDDEN
uint32_t  async_seed_get_state(ASYNC_CTX* async_ctx);

EXPORT_VISIBILITY_HIDDEN
const char* async_seed_get_name(ASYNC_CTX* async_ctx);

EXPORT_VISIBILITY_HIDDEN
KPEP_RESULT async_seed_start_thread(ASYNC_CTX *async_ctx);

#ifdef __cplusplus
}
#endif
#endif /* KPEP_ASYNC_SEED_H */
