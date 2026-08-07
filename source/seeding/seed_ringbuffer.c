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

#include <unistd.h>
#include <string.h>

#include "kpep/kpep.h"
#include "seed_ringbuffer.h"

/* ***********************************************************************************************
 * ***********************************************************************************************
 * Context
 * ***********************************************************************************************
 * ***********************************************************************************************/

typedef struct ring_ctx_st {
    uint8_t *buffer;

    size_t capacity;      /* Must be a power of two */
    size_t mask;          /* capacity - 1 */

    size_t write_pos;     /* Monotonically increasing */
    size_t read_pos;      /* Monotonically increasing */
} RING_CTX;

typedef struct ring_split_st {
    size_t index;
    size_t first;
    size_t second;
} RING_SPLIT;

/* ***********************************************************************************************
 * ***********************************************************************************************
 * Helper Functions
 * ***********************************************************************************************
 * ***********************************************************************************************/

static inline size_t ring_count(const RING_CTX *ring)
{
    return ring->write_pos - ring->read_pos;
}

static inline size_t ring_space(const RING_CTX *ring)
{
    return ring->capacity - ring_count(ring);
}

static inline RING_SPLIT ring_split(const RING_CTX *ring,
                                    size_t pos,
                                    size_t len)
{
    RING_SPLIT s;

    s.index = pos & ring->mask;

    s.first = ring->capacity - s.index;
    if (s.first > len)
        s.first = len;

    s.second = len - s.first;

    return s;
}

static inline void ring_copy_in(RING_CTX *ring,
                                size_t pos,
                                const uint8_t *restrict src,
                                size_t len)
{
    RING_SPLIT s = ring_split(ring, pos, len);

    memcpy(ring->buffer + s.index, src, s.first);

    if (s.second)
        memcpy(ring->buffer, src + s.first, s.second);
}

static inline void ring_copy_out(RING_CTX *ring,
                                 size_t pos,
                                 uint8_t *restrict dst,
                                 size_t len)
{
    RING_SPLIT s = ring_split(ring, pos, len);

    memcpy(dst, ring->buffer + s.index, s.first);

    if (s.second)
        memcpy(dst + s.first, ring->buffer, s.second);
}

static inline void ring_zero(RING_CTX *ring,
                             size_t pos,
                             size_t len)
{
    RING_SPLIT s = ring_split(ring, pos, len);

    memset(ring->buffer + s.index, 0, s.first);

    if (s.second)
        memset(ring->buffer, 0, s.second);
}

#ifdef FIPS_OPTEST
#include <assert.h>
static inline void ring_verify(const RING_CTX *ring)
{
    assert(ring != NULL);
    assert(ring->buffer != NULL);

    assert(ring->capacity != 0);
    assert((ring->capacity & (ring->capacity - 1)) == 0);
    assert(ring->mask == ring->capacity - 1);

    assert(ring->write_pos >= ring->read_pos);

    assert(ring_count(ring) <= ring->capacity);

    assert((ring->write_pos & ring->mask) < ring->capacity);
    assert((ring->read_pos & ring->mask) < ring->capacity);
}
#endif
/* ***********************************************************************************************
 * ***********************************************************************************************
 * Ring API
 * ***********************************************************************************************
 * ***********************************************************************************************/

void ring_free(RING_CTX *ring) 
{
    if (!ring)
        return;
    if (ring->buffer)
        kpep_cleanse(ring->buffer, ring->capacity);
    kpep_free(ring);
}

KPEP_RESULT ring_new(RING_CTX **ctx, size_t capacity)
{
    RING_CTX *ring;

    if (!ctx || *ctx || capacity == 0)
        return KPEP_R_INVALID_ARG;

    if ((capacity & (capacity - 1)) != 0)
        return KPEP_R_RING_NOT_POWER_OF_TWO;

    ring = kpep_zalloc(sizeof(*ring));
    if (!ring)
        return KPEP_R_MALLOC_FAIL;

    ring->buffer = kpep_zalloc(capacity);
    if (!ring->buffer) {
        kpep_free(ring);
        return KPEP_R_MALLOC_FAIL;
    }

    ring->capacity = capacity;
    ring->mask = ring->capacity - 1;

    *ctx = ring;

    return KPEP_R_SUCCESS;
}

void ring_flush(RING_CTX *ring)
{
    if (!ring)
        return;

    kpep_zeroize(ring->buffer, ring->capacity);

    ring->write_pos = 0;
    ring->read_pos = 0;
}

KPEP_RESULT ring_enqueue(RING_CTX *ring,
                         const uint8_t *restrict src,
                         size_t len)
{
    if (!ring || !src || len == 0)
        return KPEP_R_INVALID_ARG;

#ifdef FIPS_OPTEST
    ring_verify(ring);
#endif

    if (len > ring_space(ring))
        return KPEP_R_RING_FULL;
    
    ring_copy_in(ring, ring->write_pos, src, len);

    ring->write_pos += len;

#ifdef FIPS_OPTEST
    ring_verify(ring);
#endif

    return KPEP_R_SUCCESS;
}

KPEP_RESULT ring_dequeue(RING_CTX *ring,
                         uint8_t *restrict dst,
                         size_t len)
{
    if (!ring || !dst || len == 0)
        return KPEP_R_INVALID_ARG;

#ifdef FIPS_OPTEST
    ring_verify(ring);
#endif
    
    if (len > ring_count(ring))
        return KPEP_R_RING_EMPTY;

    ring_copy_out(ring, ring->read_pos, dst, len);

    ring_zero(ring, ring->read_pos, len);

    ring->read_pos += len;

    // Reset counters if empty
    if (ring->read_pos == ring->write_pos) {
        ring->read_pos = 0;
        ring->write_pos = 0;
    }

#ifdef FIPS_OPTEST
    ring_verify(ring);
#endif

    return KPEP_R_SUCCESS;
}
