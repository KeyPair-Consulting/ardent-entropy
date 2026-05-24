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

#include <string.h>

#include "openssl/params.h"
#include "openssl/core_names.h"
#include "openssl/core_dispatch.h"    /* OSSL Functions */

#include "kpep/kpep.h"
#include "hmac.h"
#include "sha2.h"

/* ************************************************************************************************
* ************************************************************************************************
* Definitions
* Careful use of these #definitions can swap an entire SHA implementation with no other changes.
* ************************************************************************************************
* ***********************************************************************************************/

/* These are local redefinitions of JEnt types/names to internal names */
#define HASH_BLOCK_SIZE      SHA2_256_BLOCK_SIZE
#define HASH_DIGEST_SIZE     SHA2_256_DIGEST_SIZE

/* Call the JEnt SHA3 functions directly */
#define hash_ctx             SHA2_CTX
#define hash_ctx_new         sha2_ctx_new
#define hash_ctx_free        sha2_ctx_free
#define hash_init            sha2_init
#define hash_update          sha2_update
#define hash_final           sha2_final
#define hash_oneshot         sha2_oneshot

/* ************************************************************************************************
* ************************************************************************************************
* HMAC-SHA3-256 functions
* ************************************************************************************************
* ***********************************************************************************************/

struct hmac_ctx_st {
    hash_ctx *ictx;
    hash_ctx *octx;

    unsigned char ipad[HASH_BLOCK_SIZE];
    unsigned char opad[HASH_BLOCK_SIZE];
};

EXPORT_VISIBILITY_HIDDEN
HMAC_CTX* hmac_ctx_new(void)
{
    HMAC_CTX* ctx;
    ctx = (HMAC_CTX*) kpep_zalloc(sizeof(HMAC_CTX));
    if (ctx) {
        ctx->ictx = hash_ctx_new();
        ctx->octx = hash_ctx_new();
        if (!ctx->ictx || !ctx->octx) {
            hash_ctx_free(ctx->ictx);  // NULL safe
            hash_ctx_free(ctx->octx);  // NULL safe
            kpep_free(ctx);
            ctx = NULL;
        }
    }

    return ctx;
}

EXPORT_VISIBILITY_HIDDEN
void hmac_ctx_free (HMAC_CTX* ctx)
{
    if (!ctx) return;
    hash_ctx_free(ctx->ictx);
    hash_ctx_free(ctx->octx);
    kpep_free(ctx);
}

EXPORT_VISIBILITY_HIDDEN
int hmac_init(HMAC_CTX *ctx, 
            const unsigned char *key, unsigned int key_size, 
            void* params)  // ossl_unused const OSSL_PARAM params[])
{
    const unsigned char *p_key;
    unsigned char key_temp[HASH_DIGEST_SIZE] = { 0 };
    int i;

    (void) params; // Unused

    if (!ctx || !key || !key_size) {
        return 0;
    }

    // Check/Prepare key and padding (Steps 1-3)
    if (key_size == HASH_BLOCK_SIZE) {
        // STEP 1: If the length of K = B: set K0 = K. Go to step 4.
        p_key = key;
    } 
    else if (key_size > HASH_BLOCK_SIZE) {
        // STEP 2:
        // If the length of K > B: hash K to obtain an L byte string, then append (B-L)
        // zeros to create a B-byte string K0 (i.e., K0 = H(K) || 00...00). Go to step 4
        // Here, B == L, so the 0x00 padding is implied below
        hash_oneshot(key, key_size, key_temp);
        p_key = key_temp;
        key_size = HASH_DIGEST_SIZE;
    }
    else { // Must be key_size < HASH_BLOCK_SIZE
        // STEP 3:
        // If the length of K < B: append zeros to the end of K to create a B-byte string K0
        // (e.g., if K is 20 bytes in length and B = 64, then K will be appended with 44
        // zero bytes x’00’).
        p_key = key;
    }

    // Prepare the ipad and opad buffers (key^pad first, then 0x00^pad after)
    for (i = 0; i < (int) key_size; i++) {
        // STEP 4: Exclusive-Or K0 with ipad to produce a B-byte string: K0 ⊕ ipad
        ctx->ipad[i] = p_key[i] ^ 0x36;
        // STEP 7: Exclusive-Or K0 with opad: K0 ⊕ opad.
        ctx->opad[i] = p_key[i] ^ 0x5c;
    }
    memset(ctx->ipad + key_size, 0x36, HASH_BLOCK_SIZE - key_size);  // (0x00 XOR pad value) for
    memset(ctx->opad + key_size, 0x5c, HASH_BLOCK_SIZE - key_size);  // everything past key_size

    // STEP 6 (Pre-compute and initial hash of the ipad buffer; use update for text/message)
    hash_init(ctx->ictx, NULL);
    hash_update(ctx->ictx, ctx->ipad, HASH_BLOCK_SIZE);

    // STEP 9 (Pre-compute the initial hash of the opad buffer; use update for final computation)
    hash_init(ctx->octx, NULL);
    hash_update(ctx->octx, ctx->opad, HASH_BLOCK_SIZE);

    return 1;
}

EXPORT_VISIBILITY_HIDDEN
int hmac_update(HMAC_CTX *ctx, 
                const unsigned char *message,
                unsigned int message_len)
{
    if (!ctx)
        return 0;

    // Steps 5 & 6
    hash_update(ctx->ictx, message, message_len);
    return 1;
}

EXPORT_VISIBILITY_HIDDEN
int hmac_final(HMAC_CTX *ctx, 
                unsigned char *mac, size_t *mac_len, 
                unsigned int mac_size)
{
    unsigned char inner_digest[HASH_DIGEST_SIZE];
    unsigned char mac_temp[HASH_DIGEST_SIZE];
    size_t tmp_len = HASH_DIGEST_SIZE;

    if (!ctx || !mac)
        return 0;

    // Finalize steps 6
    hash_final(ctx->ictx, inner_digest, &tmp_len);
    // Step 8
    hash_update(ctx->octx, inner_digest, HASH_DIGEST_SIZE);
    // Step 9
    hash_final(ctx->octx, mac_temp, mac_len);
    // Copy result
    memcpy(mac, mac_temp, mac_size);
    // If result mac length is requested, provide it
    //if (mac_len)
    //    *mac_len = HASH_DIGEST_SIZE;
    return 1;
}

EXPORT_VISIBILITY_HIDDEN
int hmac(const unsigned char *key, unsigned int key_size,
        const unsigned char *message, unsigned int message_len,
        unsigned char *mac, unsigned int mac_size)
{
    int rv = 1;  // Assume success
    HMAC_CTX *ctx = NULL;
    if ((NULL == (ctx = hmac_ctx_new())) ||
        !hmac_init(ctx, key, key_size, NULL) ||
        !hmac_update(ctx, message, message_len) ||
        !hmac_final(ctx, mac, NULL, mac_size))
        rv =  0;
    if (ctx)
        hmac_ctx_free(ctx);
    return rv;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * Algorithm Implementation Interface
 * ************************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
const OSSL_DISPATCH kpep_hmac_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX,  (void (*)(void))hmac_ctx_new },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void))hmac_ctx_free },
    { OSSL_FUNC_MAC_INIT,    (void (*)(void))hmac_init },
    { OSSL_FUNC_MAC_UPDATE,  (void (*)(void))hmac_update },
    { OSSL_FUNC_MAC_FINAL,   (void (*)(void))hmac_final },
    OSSL_DISPATCH_END
};
