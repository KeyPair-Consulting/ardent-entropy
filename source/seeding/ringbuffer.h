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

#ifndef SEED_RINGBUFFER_H
#define SEED_RINGBUFFER_H
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ring_ctx_st RING_CTX;

/**
 * Create a new ring buffer context
 * @param ctx Dbl-Pointer to a ring buffer structure to be created
 * @param size The number of bytes (size-1) that can be stored in the ring.  Must be a power-of-2.
 * @return TOOLBOX_RESULT (zero on success, otherwise specified error)
 */
ARDENT_RESULT ring_new(RING_CTX** ctx, size_t size);

/**
 * Free the ring buffer context and all allocated memory
 * @param ctx The ring buffer to be freed.  All bytes are zeroized.
 */
void ring_free(RING_CTX *ctx);

/**
 * Flush/Reset the buffer
 * @param ctx The ring buffer to be flushed/reset.  All bytes are zeroized.
 */
void ring_flush(RING_CTX *ctx);

/**
 * Returns the number of items in the ring buffer.
 * @param ctx The ring buffer to query.
 * @return The number of items in the ring buffer.
 */
size_t ring_count(const RING_CTX* ctx);

/**
 * Returns the space available oo the ring buffer.
 * @param ctx The ring buffer the query.
 * @return The number of items that can be stored in the ring buffer.
 */
size_t ring_space(const RING_CTX* ctx);

/**
 * Add bytes to the ring as found in the buffer.
 * @param ctx The ring buffer to which the bytes should be enqueued.
 * @param buf The ring from which the bytes should be copied.
 * @param buflen The number of bytes to copy/add
 * @return TOOLBOX_RESULT (zero on success, otherwise specified error)
 */
ARDENT_RESULT ring_enqueue(RING_CTX* ctx, const uint8_t *restrict buf, size_t buflen);

/**
 * Remove bytes from the ring and place them in the buffer.  Removed bytes in ring are zeroized.
 * @param ctx The ring buffer from which the bytes should be dequeued.
 * @param buf The buffer for which it should be returned whether it is empty.
 * @param buflen The number of bytes to return
 * @return TOOLBOX_RESULT (zero on success, otherwise specified error)
 */
ARDENT_RESULT ring_dequeue(RING_CTX* ctx, uint8_t *restrict buf, size_t buflen);

#ifdef __cplusplus
}
#endif
#endif /* SEED_RINGBUFFER_H */