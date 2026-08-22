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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "kpep/kpep.h"
#include "sha2.h"
#include "drbg.h"
#include "../seeding/seed_control.h"

/* ************************************************************************************************
 * ************************************************************************************************
 * Definitions
 * ************************************************************************************************
 * ***********************************************************************************************/

#define MODULE_NAME "KPEP-DRBG"

// Seed length for SHA2-256
#define SEED_BYTE_LENGTH    (uint32_t) (55)

struct kpep_drbg_ctx_st {
	// State
	uint32_t running;

	// External Contexts
	SHA2_CTX         *hash_ctx;
	SEED_CONTROL_CTX *seed_ctx;

	// Internal State
	uint8_t V[SEED_BYTE_LENGTH];
	uint8_t C[SEED_BYTE_LENGTH];
};

#ifdef DEBUG_DRBG
static void print_bytes(const uint8_t *buf, const uint32_t len, const uint32_t indent)
{
	uint32_t index;
	if (indent)
		printf("%*s", indent, "");
	if (!buf || len == 0)
		printf("(null)");
	for (index=0; index<len; index++) {
		printf("%02x", buf[index]);
	}
}
#endif

/* ************************************************************************************************
 * ************************************************************************************************
 * OpenSSL interface for context
 * ************************************************************************************************
 * ***********************************************************************************************/

#ifdef FIPS_ACVP
EXPORT_VISIBILITY_DEFAULT
#else
EXPORT_VISIBILITY_HIDDEN
#endif
void* drbg_new(void *vctx, KPEP_RESULT *errnum) 
{
	KPEP_DRBG_CTX* ctx = NULL;

	if (kpep_trace_seed_enabled) {
		TRACE_START;
	}

	// Allocate for DRBG context
	ctx = (KPEP_DRBG_CTX*) kpep_zalloc(sizeof(KPEP_DRBG_CTX));
	if (!ctx) {
		LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_MALLOC_FAIL);
		if (errnum) *errnum = KPEP_R_MALLOC_FAIL;
		return NULL;
	}

	// Allocate for the SHA Context
	ctx->hash_ctx = sha2_ctx_new();
	if (!ctx->hash_ctx) {
		LOG_KPEP_ERROR(MODULE_NAME, KPEP_R_INTERNAL_HASH_FAIL);
		if (errnum) *errnum = KPEP_R_INTERNAL_HASH_FAIL;
		kpep_free(ctx);  // Nothing to zeroize
		return NULL;
	}

	// Set the seed control context
	ctx->seed_ctx = (SEED_CONTROL_CTX*) vctx;

	// Setup parameters
	// None

	return ctx;
}

#ifdef FIPS_ACVP
EXPORT_VISIBILITY_DEFAULT
#else
EXPORT_VISIBILITY_HIDDEN
#endif
void drbg_free(KPEP_DRBG_CTX* ctx) 
{
	if (kpep_trace_seed_enabled) {
		TRACE_START;
	}
	if (ctx) {
		sha2_ctx_free(ctx->hash_ctx);              // NULL check inside
		kpep_cleanse(ctx, sizeof(KPEP_DRBG_CTX));  // Zeroize before Free
	}
}

/* ************************************************************************************************
 * ************************************************************************************************
 * Derivation Function (SP800-90Ar1, section 10.3.1; pg 58)
 * ************************************************************************************************
 * ***********************************************************************************************/

static 
KPEP_RESULT hash_df(KPEP_DRBG_CTX* ctx, 
                    uint8_t* output, uint32_t output_len,
                    uint8_t* input, uint32_t input_len) 
{
	uint32_t remaining = output_len;
	uint32_t output_len_bits;
    uint8_t output_len_bytes[5];
	uint8_t digest[64];
	uint8_t *p = output;

	if (!output || output_len == 0 || !input || input_len == 0 ||
	    output_len > (255 *SHA2_256_DIGEST_SIZE)) {
		return KPEP_R_INVALID_ARG;	
	}

	// Counter plus 32-bit int as bytes (big-endian)
	output_len_bits = output_len << 3;  // To bits
	output_len_bytes[0] = 0x01;  // Counter
	output_len_bytes[1] = (uint8_t)((output_len_bits >> 24) & 0xFF);
	output_len_bytes[2] = (uint8_t)((output_len_bits >> 16) & 0xFF);
	output_len_bytes[3] = (uint8_t)((output_len_bits >>  8) & 0xFF);
	output_len_bytes[4] = (uint8_t)((output_len_bits      ) & 0xFF);

	while (remaining > 0) {
		// Do derivation hash
		sha2_init  (ctx->hash_ctx, NULL);
		sha2_update(ctx->hash_ctx, output_len_bytes, 5);
		sha2_update(ctx->hash_ctx, input, input_len);
		sha2_final (ctx->hash_ctx, digest, NULL);

		// Full or partial block?
		if (remaining >SHA2_256_DIGEST_SIZE) {
			memcpy(p, digest,SHA2_256_DIGEST_SIZE);
			remaining -=SHA2_256_DIGEST_SIZE;
			p +=SHA2_256_DIGEST_SIZE;
		}
		else {
			memcpy(p, digest, remaining);
			remaining = 0;
		}

		// Update the counter
		output_len_bytes[0] += 1;
	}

#ifdef DEBUG_DRBG
	kpep_trace(MODULE_NAME, "HASH_DF");
	printf("Output: \n");
	print_bytes(output, SEED_BYTE_LENGTH, 4); printf("\n");
#endif

	return KPEP_R_SUCCESS;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * INSTANTIATE (SP800-90Ar1, section 10.1.1.2; pg 39)
 * ************************************************************************************************
 * ***********************************************************************************************/

#ifdef FIPS_ACVP
EXPORT_VISIBILITY_DEFAULT
#else
EXPORT_VISIBILITY_HIDDEN
#endif
KPEP_RESULT drbg_instantiate_ex(KPEP_DRBG_CTX* ctx, int strength_bits,
    							const uint8_t* entropy, uint32_t entropy_len, 
    							const uint8_t* nonce, uint32_t nonce_len, 
    							const uint8_t* pers, uint32_t pers_len)
{
	KPEP_RESULT rv = KPEP_R_SUCCESS; // Assume success
	uint32_t buffer_len;
	uint8_t *p, *buffer = NULL;

#ifdef DEBUG_DRBG
	kpep_trace(MODULE_NAME, "INSTANTIATE_EX");
	printf("Entropy: \n");
	print_bytes(entropy, entropy_len, 4); printf("\n");
	printf("Nonce  : \n");
	print_bytes(nonce, nonce_len, 4); printf("\n");
	printf("Pers   : \n");
	print_bytes(pers, pers_len, 4); printf("\n");
#endif

	// Validate inputs
	if (!ctx 
		|| (strength_bits > 256) 
		|| (pers_len > MAX_PERS_LEN) 
		|| (nonce_len > MAX_NONCE_LEN)
		|| (entropy_len > MAX_ENTROPY_LEN)) {
		return KPEP_R_INVALID_ARG;
	}

	// Refresh the Hash context
	sha2_ctx_free(ctx->hash_ctx);
	ctx->hash_ctx = sha2_ctx_new();
	if (!ctx->hash_ctx) {
		return KPEP_R_MALLOC_FAIL;
	}

	// C-style Try/Finally block
	do {
		// 1. seed_material = entropy_input || nonce || personalization_string.
		// 2. seed = Hash_df (seed_material, seedlen).
		// 3. V = seed.
		buffer_len = entropy_len + nonce_len + pers_len;
		buffer = (uint8_t*) kpep_zalloc(buffer_len);
		if (!buffer) {
			rv = KPEP_R_MALLOC_FAIL;
			break;
		}
		p = buffer;
		memcpy(p, entropy, entropy_len);
		p += entropy_len;
		if (nonce && nonce_len>0) {
			memcpy(p, nonce, nonce_len);
			p += nonce_len;
		}
		if (pers && pers_len>0) {
			memcpy(p, pers, pers_len);
		}
		rv = hash_df(ctx, ctx->V, SEED_BYTE_LENGTH, buffer, buffer_len); 
		if (rv) {
			break;
		}

		// Cleanup for re-use
		kpep_cleanse(buffer, buffer_len);
		buffer = NULL;
		
		// 4. C = Hash_df ((0x00 || V), seedlen);  Comment: Precede V with a byte of zeros.
		buffer_len = SEED_BYTE_LENGTH+1;
		buffer = (uint8_t*) kpep_zalloc(buffer_len);
		if (!buffer) {
			rv = KPEP_R_MALLOC_FAIL;
			break;
		}
		buffer[0] = 0x00;
		memcpy(buffer+1, ctx->V, SEED_BYTE_LENGTH);
		rv = hash_df(ctx, ctx->C, SEED_BYTE_LENGTH, buffer, buffer_len); 
		if (rv) {
			break;
		}
		// kpmmp_cleanse(buffer, buffer_len); performed below!
		
		// 5. reseed_counter = 1.
		// Prediction Resistance is always ON, so we don't maintain a reseed counter

		// 7. Return (V, C, reseed_counter).
		// N/A: Values saved inside the context

#ifdef DEBUG_DRBG
		printf("V: \n");
		print_bytes(ctx->V, SEED_BYTE_LENGTH, 4); printf("\n");
		printf("C: \n");
		print_bytes(ctx->C, SEED_BYTE_LENGTH, 4); printf("\n");
#endif

		// Success
		ctx->running = 1;
	} while (0);

	// Cleanup
	kpep_cleanse(buffer, buffer_len);
	
	// Reset/Zeroize state on failure
	if (rv) {
		// Zeroize state
		memset(ctx->C, 0, sizeof(SEED_BYTE_LENGTH));
		memset(ctx->V, 0, sizeof(SEED_BYTE_LENGTH));
	}
	return rv;  
}

#ifdef FIPS_ACVP
EXPORT_VISIBILITY_DEFAULT
#else
EXPORT_VISIBILITY_HIDDEN
#endif
void drbg_uninstantiate(KPEP_DRBG_CTX* ctx)
{
	if (kpep_trace_seed_enabled) {
		TRACE_START;
	}
	if (ctx) {
		ctx->running = 0;
		/* ZEROIZE */
		memset(ctx->C, 0, SEED_BYTE_LENGTH);
		memset(ctx->V, 0, SEED_BYTE_LENGTH);
	}
}

#ifdef FIPS_ACVP
EXPORT_VISIBILITY_DEFAULT
#else
EXPORT_VISIBILITY_HIDDEN
#endif
int  drbg_verify_zeroization(KPEP_DRBG_CTX* ctx)
{
	size_t i;
	if (!ctx)
		return 1; // OK
	for (i=0; i<SEED_BYTE_LENGTH; ++i) {
		if (ctx->C[i] || ctx->V[i])
			return 0;
	}
	return 1;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * RESEED  (SP800-90Ar1, section 10.1.1.3; pg 40)
 * ************************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
KPEP_RESULT drbg_reseed_ex(KPEP_DRBG_CTX* ctx, 
				        	const uint8_t *entropy, size_t entropy_len,
				        	const uint8_t *addl, size_t addl_len)
{
	KPEP_RESULT rv = 0;  // Assume success
	uint32_t buffer_len;
	uint8_t *p, *buffer = NULL;

	if (kpep_trace_seed_enabled) {
		TRACE_START;
	}

	if (!ctx || (addl_len > MAX_ADDL_LEN)) {
		return KPEP_R_INVALID_ARG;
	}
	if (!entropy || (entropy_len < KPEP_SECURITY_STRENGTH_BITS>>3)) {
		return KPEP_R_DRBG_INSUFFICIENT_ENTROPY;
	}
	if (!ctx->running) {
		return KPEP_R_DRBG_INVALID_STATE;
	}

#ifdef DEBUG_DRBG
	kpep_trace(MODULE_NAME, "RESEED_EX");
	printf("Entropy: \n");
	print_bytes(entropy, entropy_len, 4); printf("\n");
	printf("Addin  : \n");
	print_bytes(addl, addl_len, 4); printf("\n");
#endif

	do {
		// 1. seed_material = 0x01 || V || entropy_input || additional_input.
		// 2. seed = Hash_df (seed_material, seedlen).
		// 3. V = seed.
		buffer_len = 1 + SEED_BYTE_LENGTH + entropy_len + addl_len;
		buffer = (uint8_t*) kpep_zalloc(buffer_len);
		if (!buffer) {
			rv = KPEP_R_MALLOC_FAIL;
			break;
		}
		buffer[0] = 0x01;
		p = buffer+1;
		memcpy(p, ctx->V, SEED_BYTE_LENGTH);
		p += SEED_BYTE_LENGTH;
		memcpy(p, entropy, entropy_len);
		p += entropy_len;
		if (addl_len > 0) {
			memcpy(p, addl, addl_len);
		}
		rv = hash_df(ctx, ctx->V, SEED_BYTE_LENGTH, buffer, buffer_len); 
		if (rv) {
			break;
		}

		// Cleanup for re-use
		kpep_cleanse(buffer, buffer_len);
		buffer = NULL;

		// 4. C = Hash_df ((0x00 || V), seedlen).
		buffer_len = SEED_BYTE_LENGTH + 1;
		buffer = (uint8_t*) kpep_zalloc(buffer_len);
		if (!buffer) {
			rv = KPEP_R_MALLOC_FAIL;
			break;
		}
		buffer[0] = 0x00;
		memcpy(buffer+1, ctx->V, SEED_BYTE_LENGTH);
		rv = hash_df(ctx, ctx->C, SEED_BYTE_LENGTH, buffer, buffer_len);
		if (rv) {
			break;
		}
		// kpep_cleanse(buffer, buffer_len); // Performed below at cleanup

		// 5. reseed_counter = 1.
		// Prediction Resistance is always ON

		// 6. Return (V, C, and reseed_counter).
		// N/A: Values saved inside the context
	} while(0);

#ifdef DEBUG_DRBG
		printf("V: \n");
		print_bytes(ctx->V, SEED_BYTE_LENGTH, 4); printf("\n");
		printf("C: \n");
		print_bytes(ctx->C, SEED_BYTE_LENGTH, 4); printf("\n");
#endif

	// Cleanup
	kpep_cleanse(buffer, buffer_len);

	return rv;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * GENERATE (SP800-90Ar1, section 10.1.1.4; pg 41)
 * ************************************************************************************************
 * ***********************************************************************************************/

/*
 * Increment buffer
 * FROM: https://github.com/torvalds/linux/blob/master/crypto/drbg.c
 *
 * @dst buffer to increment
 * @add value to add
 */
/* 
 * NOTE: A similar algorithm can be found in OpenSSL 3.0.x --
 * providers/implementations/rands/drbg_hash.c:~144
 */
static inline 
void drbg_add_buf(unsigned char *dst, size_t dstlen,
                  const unsigned char *add, size_t addlen)
{
	/* implied: dstlen > addlen */
	unsigned char *dstptr;
	const unsigned char *addptr;
	unsigned int remainder = 0;
	size_t len = addlen;

	dstptr = dst + (dstlen-1);
	addptr = add + (addlen-1);
	while (len) {
		remainder += *dstptr + *addptr;
		*dstptr = remainder & 0xff;
		remainder >>= 8;
		len--; dstptr--; addptr--;
	}
	len = dstlen - addlen;
	while (len && remainder > 0) {
		remainder = *dstptr + 1;
		*dstptr = remainder & 0xff;
		remainder >>= 8;
		len--; dstptr--;
	}
}

static 
KPEP_RESULT hash_gen(KPEP_DRBG_CTX* ctx, uint8_t *rand, uint32_t rand_len)
{
	const uint8_t one[1] = { 0x01 };
	uint8_t data[256];
	uint8_t digest[64];
	uint32_t remaining;
	uint8_t *w = rand;  // rand is 'W', this 'w' starts at [0]

	remaining = rand_len;
	if (remaining > DRBG_MAX_BYTES_PER_REQUEST) {
		return KPEP_R_DRBG_REQUEST_TOO_LARGE;
	}

	if (!ctx || !rand || !rand_len) {
		return KPEP_R_INVALID_ARG;
	}

	if (!ctx->running) {
		return KPEP_R_DRBG_INVALID_STATE;
	}

	// 1. m = ciel(nbits/outlen)
	// N/A; we're doing a while()

	// 2. data = V.
	memcpy(data, ctx->V, SEED_BYTE_LENGTH);

	// 3. W = the Null string.
	memset(rand, 0, remaining);

	// 4. For i = 1 to m
	while (remaining > 0) {
		// 4.1 w = Hash (data).
		if (!sha2_oneshot(data, SEED_BYTE_LENGTH, digest)) {
			return KPEP_R_INTERNAL_HASH_FAIL;
		}

		// Partial block, exit here?
		if (remaining <SHA2_256_DIGEST_SIZE) {
			// 5. returned_bits = leftmost (W, requested_no_of_bits).
			memcpy(w, digest, remaining);  // Copy only what we need
			remaining = 0;
			break;
		}

		// 4.2 W = W || w.
		memcpy(w, digest,SHA2_256_DIGEST_SIZE);  // Copy entire block
		remaining -=SHA2_256_DIGEST_SIZE;
		w +=SHA2_256_DIGEST_SIZE;
		
		// 4.3 data = (data + 1) mod 2^seedlen .
		drbg_add_buf(data, SEED_BYTE_LENGTH, one, 1);
	}

	return KPEP_R_SUCCESS;
}

#ifdef FIPS_ACVP
EXPORT_VISIBILITY_DEFAULT
#else
EXPORT_VISIBILITY_HIDDEN
#endif
KPEP_RESULT drbg_generate_ex(KPEP_DRBG_CTX* ctx, 
	                       	 uint8_t *rand, uint32_t rand_len,
							 const uint8_t *entropy, size_t entropy_len,
	                       	 const uint8_t *addl, uint32_t addl_len)
{
	KPEP_RESULT rv = KPEP_R_SUCCESS;  // Assume success

	uint8_t *buffer = NULL;
	uint8_t H[64] = { 0 };

	if (kpep_trace_seed_enabled) {
		TRACE_START;
	}

	if (!ctx)
		return KPEP_R_NULL_ARG;
	if (!rand || rand_len == 0)
		return KPEP_R_INVALID_ARG;

	if (!ctx->running) {
		return KPEP_R_DRBG_INVALID_STATE;
	}

	// 1. If reseed_counter > reseed_interval, then return an indication that a reseed is required.
	// Prediction Resistance is always ON

	// Prediction Resistance ALWAYS ON; Reseed w/ Add'l Input
	rv = drbg_reseed_ex(ctx, entropy, entropy_len, addl, addl_len);
	if (rv)
		return rv;

#ifdef DEBUG_DRBG
	kpep_trace(MODULE_NAME, "GENERATE_EX");
#endif

	do {
		// 3. (returned_bits) = Hashgen (requested_number_of_bits, V).
		rv = hash_gen(ctx, rand, rand_len);
		if (rv) {
			break;
		}

		// 4. H = Hash (0x03 || V).
		buffer = (uint8_t*) kpep_zalloc(SEED_BYTE_LENGTH+1);
		if (!buffer) {
			rv = KPEP_R_MALLOC_FAIL;
			break;
		}
		buffer[0] = 0x03;
		memcpy(buffer+1, ctx->V, SEED_BYTE_LENGTH);
		sha2_oneshot(buffer, SEED_BYTE_LENGTH+1, H); 

		// 5. V = (V + H + C + reseed_counter) mod 2^seedlen.
		drbg_add_buf(ctx->V, SEED_BYTE_LENGTH, H,SHA2_256_DIGEST_SIZE);
		drbg_add_buf(ctx->V, SEED_BYTE_LENGTH, ctx->C, SEED_BYTE_LENGTH);
		// Prediction Resistance is always ON, so reseed_counter is always 1
		H[0] = 1;
		drbg_add_buf(ctx->V, SEED_BYTE_LENGTH, H, 1);

		// 6. reseed_counter = reseed_counter + 1.
		// Prediction Resistance is always ON

		// 7. Return (SUCCESS, returned_bits, V, C, reseed_counter).
		// N/A, values saved in context
	} while (0);

#ifdef DEBUG_DRBG
		printf("V: \n");
		print_bytes(ctx->V, SEED_BYTE_LENGTH, 4); printf("\n");
		printf("C: \n");
		print_bytes(ctx->C, SEED_BYTE_LENGTH, 4); printf("\n");
#endif

	// Cleanup state and temp
	kpep_cleanse(buffer, SEED_BYTE_LENGTH+1);  // NULL safe
	memset(H, 0, sizeof(H));                   // Zeroize

	return rv;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * WRAPPER FUNCTIONS
 * ************************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_HIDDEN
KPEP_RESULT drbg_instantiate(KPEP_DRBG_CTX* ctx, int strength_bits, const uint8_t* perso, uint32_t perso_len)
{
	KPEP_RESULT rv = KPEP_R_SUCCESS;
	uint8_t *entropy = NULL;
	uint8_t *nonce = NULL;
	size_t ent_len = 0, nonce_len = 0;

	if (kpep_trace_seed_enabled) {
		TRACE_START;
	}

	if (!ctx)
		return KPEP_R_NULL_ARG;

	do {
		// Gather entropy
		rv = seed_control_gather(ctx->seed_ctx, &entropy, &ent_len, KPEP_SECURITY_STRENGTH_BITS, 1); // Validated
		if (rv) {
			// Logged in seed_control.c with better context
			//LOG_KPEP_ERROR(MODULE_NAME, rv);
			break;
		}
		// Gather Nonce; STRENGTH_BITS/2 (see SP 800-90Ar1 section 8.6.7)
		rv = seed_control_gather(ctx->seed_ctx, &nonce, &nonce_len, KPEP_SECURITY_STRENGTH_BITS/2, 1); // Validated
		if (rv) {
			// Logged in seed_control.c with better context
			//LOG_KPEP_ERROR(MODULE_NAME, rv);
			break;
		}
		// Call the instantiate function
		rv = drbg_instantiate_ex(ctx, KPEP_SECURITY_STRENGTH_BITS, 
			                	entropy, ent_len,
								nonce, nonce_len,
								perso, perso_len);
	} while (0);

	// Free the seed buffers
	kpep_cleanse(entropy, ent_len);
	kpep_cleanse(nonce, nonce_len);

	return rv;
}

EXPORT_VISIBILITY_HIDDEN
KPEP_RESULT drbg_generate(KPEP_DRBG_CTX* ctx, uint8_t *rand, uint32_t rand_len)
{
	KPEP_RESULT rv = KPEP_R_SUCCESS;
	uint8_t *entropy = NULL;
	uint8_t *addl = NULL;
	size_t   ent_len = 0, addl_len = 0;
	
	size_t  cur_len = 0;
	uint8_t drbg_out[KPEP_SECURITY_STRENGTH_BYTES];

	if (kpep_trace_seed_enabled) {
		kpep_trace_fmt(MODULE_NAME, "%s (req %u)", __func__, rand_len<<3);
	}

	// Validate
	if (!ctx) {
		rv = KPEP_R_NULL_ARG;
	}
	if (!rand) {
		rv = KPEP_R_INVALID_ARG;
	}
	if (!rand_len) {
		return KPEP_R_SUCCESS;
	}
	if (rv) {
		LOG_KPEP_ERROR(MODULE_NAME, rv);
		return rv;
	}

	// Gather entropy
	do {
		// Need to pull in STRENGTH_BITS + 64 bits for RBGC(RS) (see SP 800-90C section 6.5.1.2, in particular step 3.1)
		rv = seed_control_gather(ctx->seed_ctx, &entropy, &ent_len, KPEP_SECURITY_STRENGTH_BITS+64, 1); // Validated
		if (rv) {
			// Logged in seed_control.c with better context
			//LOG_KPEP_ERROR(MODULE_NAME, rv);
			break;
		}
		// Gather additional input
		// Same size as above
		rv = seed_control_gather(ctx->seed_ctx, &addl, &addl_len, KPEP_SECURITY_STRENGTH_BITS+64, 0); // Non-Validated
		if (rv) {
			// Logged in seed_control.c with better context
			//LOG_KPEP_ERROR(MODULE_NAME, rv);
			break;
		}
		// Call the generate function, gathering no more than SECURITY_STRENGTH bytes per request
		// (see SP 800-90C section 6.5.1.2, step 3.2)
		rv = drbg_generate_ex(  ctx, 
			                    drbg_out, KPEP_SECURITY_STRENGTH_BYTES,
			                    entropy, ent_len,
								addl, addl_len);
		if (rv) {
			LOG_KPEP_ERROR(MODULE_NAME, rv);
			break;
		}
		// Truncate the last block as required (see SP 800-90C section 6.5.1.2, step 4)
		cur_len = (rand_len<KPEP_SECURITY_STRENGTH_BYTES)?rand_len:KPEP_SECURITY_STRENGTH_BYTES;

		// Copy out and update
		memcpy(rand, drbg_out, cur_len);
		rand += cur_len;
		rand_len -= cur_len;
	} while (rand_len > 0);
									
	// Free the seed buffers
	kpep_cleanse(entropy, ent_len);
	kpep_cleanse(addl, addl_len);
	
	return rv;
}
