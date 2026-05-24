/*
    MIT License

    Copyright (c) 2020 LekKit https://github.com/LekKit

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
 */
/* 
 * Original source: https://github.com/LekKit/sha256
 * Details of the implementation, etc can be found here: https://en.wikipedia.org/wiki/SHA-2 
 */
/* 
 * CHANGES ONLY:
 *
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
 * 
 * CHANGELOG:
 * Changes to support integration with  and OpenSSL algorithm requirements 
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "openssl/err.h"
#include "openssl/core_names.h"
#include "openssl/core_dispatch.h"    /* OSSL Functions */
#include "openssl/params.h"

#include "kpep/kpep.h"
#include "sha2.h"

/* ************************************************************************************************
 * SHA2 context structure
 * ***********************************************************************************************/

struct sha2_ctx_st {
    uint64_t data_size;
    uint32_t h[8];
    uint8_t  last_chunk[64];
    uint8_t  chunk_size;
};

/* ************************************************************************************************
 * SHA2 Backend
 * ***********************************************************************************************/

#define rotate_r(val, bits) (val >> bits | val << (32 - bits))

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_calc_chunk(SHA2_CTX* ctx, const uint8_t* chunk) 
{
    uint32_t w[64];
    uint32_t tv[8];
    uint32_t i;

    for (i=0; i<16; ++i){
        w[i] = (uint32_t) chunk[0] << 24 | (uint32_t) chunk[1] << 16 | (uint32_t) chunk[2] << 8 | (uint32_t) chunk[3];
        chunk += 4;
    }
    
    for (i=16; i<64; ++i){
        uint32_t s0 = rotate_r(w[i-15], 7) ^ rotate_r(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotate_r(w[i-2], 17) ^ rotate_r(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    
    for (i = 0; i < 8; ++i)
        tv[i] = ctx->h[i];
    
    for (i=0; i<64; ++i){
        uint32_t S1 = rotate_r(tv[4], 6) ^ rotate_r(tv[4], 11) ^ rotate_r(tv[4], 25);
        uint32_t ch = (tv[4] & tv[5]) ^ (~tv[4] & tv[6]);
        uint32_t temp1 = tv[7] + S1 + ch + k[i] + w[i];
        uint32_t S0 = rotate_r(tv[0], 2) ^ rotate_r(tv[0], 13) ^ rotate_r(tv[0], 22);
        uint32_t maj = (tv[0] & tv[1]) ^ (tv[0] & tv[2]) ^ (tv[1] & tv[2]);
        uint32_t temp2 = S0 + maj;
        
        tv[7] = tv[6];
        tv[6] = tv[5];
        tv[5] = tv[4];
        tv[4] = tv[3] + temp1;
        tv[3] = tv[2];
        tv[2] = tv[1];
        tv[1] = tv[0];
        tv[0] = temp1 + temp2;
    }

    for (i = 0; i < 8; ++i)
        ctx->h[i] += tv[i];
}

/* ************************************************************************************************
 * OpenSSL Interface
 * ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
SHA2_CTX* sha2_ctx_new(void)
{
    return kpep_zalloc(sizeof(SHA2_CTX));
}

EXPORT_VISIBILITY_HIDDEN
void sha2_ctx_free(SHA2_CTX* ctx)
{
    kpep_cleanse(ctx, sizeof(SHA2_CTX)); // Zeroize before Free; NULL safely handled
}

EXPORT_VISIBILITY_HIDDEN
void* sha2_ctx_dup(void* ctx)
{
    SHA2_CTX* new_ctx = NULL;

    // Validate argument and allocate new
    if (ctx && (new_ctx = sha2_ctx_new())) {
        memcpy(new_ctx, ctx, sizeof(SHA2_CTX));
    }

    return new_ctx;
}

EXPORT_VISIBILITY_HIDDEN
int sha2_zeroize(SHA2_CTX* ctx)
{
   if (!ctx) return 0;
   memset(ctx, 0, sizeof(SHA2_CTX));
   return 1; 
}

EXPORT_VISIBILITY_HIDDEN
int sha2_init(SHA2_CTX* ctx, const OSSL_PARAM params[])
{
    if (!ctx) return 0;
    ctx->h[0] = 0x6a09e667;
    ctx->h[1] = 0xbb67ae85;
    ctx->h[2] = 0x3c6ef372;
    ctx->h[3] = 0xa54ff53a;
    ctx->h[4] = 0x510e527f;
    ctx->h[5] = 0x9b05688c;
    ctx->h[6] = 0x1f83d9ab;
    ctx->h[7] = 0x5be0cd19;
    ctx->data_size = 0;
    ctx->chunk_size = 0;
    return 1;
}

EXPORT_VISIBILITY_HIDDEN
int sha2_update(SHA2_CTX* ctx, const unsigned char* msg, size_t size) 
{
    if (!ctx || !msg) return 0;
    ctx->data_size += size;

    /* If there is data left in ctx, concatenate it to process as new chunk */
    if (size + ctx->chunk_size >= 64) {
        uint8_t tmp_chunk[64];
        memcpy(tmp_chunk, ctx->last_chunk, ctx->chunk_size);
        memcpy(tmp_chunk + ctx->chunk_size, msg, 64 - ctx->chunk_size);
        msg += (64 - ctx->chunk_size);
        size -= (64 - ctx->chunk_size);
        ctx->chunk_size = 0;
        sha256_calc_chunk(ctx, tmp_chunk);
    }
    /* Run over data chunks */
    while (size  >= 64) {
        sha256_calc_chunk(ctx, msg);
        msg += 64;
        size -= 64; 
    }
    
    /* Save remaining data in ctx, will be reused on next call or finalize */
    memcpy(ctx->last_chunk + ctx->chunk_size, msg, size);
    ctx->chunk_size += size;

    return 1;
}

EXPORT_VISIBILITY_HIDDEN
int sha2_final(SHA2_CTX* ctx, uint8_t* digest, size_t* digest_len) 
{
    uint64_t size;
    int i;

    if (!ctx) return 0;

    /* Only if digest is given */
    if (digest) {
        ctx->last_chunk[ctx->chunk_size] = 0x80;
        ctx->chunk_size++;
        memset(ctx->last_chunk + ctx->chunk_size, 0, 64 - ctx->chunk_size);

        /* If there isn't enough space to fit int64, pad chunk with zeroes and prepare next chunk */
        if (ctx->chunk_size > 56) {
            sha256_calc_chunk(ctx, ctx->last_chunk);
            memset(ctx->last_chunk, 0, 64);
        }

        /* Add total size as big-endian int64 x8 */
        size = ctx->data_size * 8;
        for (i = 8; i > 0; --i) {
            ctx->last_chunk[55+i] = size & 255;
            size >>= 8;
        }

        sha256_calc_chunk(ctx, ctx->last_chunk);

        for (i = 0; i < 8; i++) {
            digest[i*4]     = (ctx->h[i] >> 24) & 255;
            digest[i*4 + 1] = (ctx->h[i] >> 16) & 255;
            digest[i*4 + 2] = (ctx->h[i] >> 8)  & 255;
            digest[i*4 + 3] = (ctx->h[i])       & 255;
        }
    }
    if (digest_len)
        *digest_len = SHA2_256_DIGEST_SIZE;
    return 1;
}

EXPORT_VISIBILITY_HIDDEN
int sha2_oneshot(const unsigned char* message, unsigned int len, unsigned char* digest) {
    SHA2_CTX ctx;
    return (sha2_init(&ctx, NULL) && 
            sha2_update(&ctx, message, len) &&
            sha2_final(&ctx, digest, NULL));
}

static const OSSL_PARAM kpep_sha2_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_END
};

EXPORT_VISIBILITY_HIDDEN
const OSSL_PARAM *sha2_gettable_params(void *provctx)
{
    return kpep_sha2_known_gettable_params;
}

EXPORT_VISIBILITY_HIDDEN
int sha2_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, SHA2_256_BLOCK_SIZE)) {
        kpep_log(LOG_LVL_ERR, "SHA2", "Failed to set parameter 'blocksize'");
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, SHA2_256_DIGEST_SIZE)) {
        kpep_log(LOG_LVL_ERR, "SHA2", "Failed to set parameter 'size'");
        return 0;
    }
    return 1;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * Algorithm Implementation Interface
 * ************************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
const OSSL_DISPATCH kpep_sha2_digest_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,          (void (*)(void))sha2_ctx_new },
    { OSSL_FUNC_DIGEST_FREECTX,         (void (*)(void))sha2_ctx_free },
    { OSSL_FUNC_DIGEST_DUPCTX,          (void (*)(void))sha2_ctx_dup },
    { OSSL_FUNC_DIGEST_INIT,            (void (*)(void))sha2_init },
    { OSSL_FUNC_DIGEST_UPDATE,          (void (*)(void))sha2_update },
    { OSSL_FUNC_DIGEST_FINAL,           (void (*)(void))sha2_final },
    { OSSL_FUNC_DIGEST_GET_PARAMS,      (void (*)(void))sha2_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))sha2_gettable_params },
    OSSL_DISPATCH_END
};
