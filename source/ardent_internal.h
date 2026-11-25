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

#ifndef ARDENT_INTERNAL_H
#define ARDENT_INTERNAL_H
#pragma once

#include "ardent/ardent.h"  // For ARDENT_RESULT

#ifdef __cplusplus
extern "C" {
#endif

/* ************************************************************************************************
 * SEED-SOURCE descriptions and Mode
 * ***********************************************************************************************/

typedef struct ardent_seeding_ctx_st ARDENT_SEEDING_CTX;

// Get a multi-line string containing a description of all the seed sources, one per line; source in ardent_seeding.c
const char* ardent_seeding_get_description(ARDENT_SEEDING_CTX *ctx);

// Get a boolean (0/1) whether entropy restrive counting (Method #1) is enabled
int ardent_seeding_get_restricted_mode(ARDENT_SEEDING_CTX *ctx);

// Retrieve the seeding service owned by a provider context.
ARDENT_SEEDING_CTX *ardent_provider_get_seeding(void *prov_ctx);

/* ************************************************************************************************
 * ERROR Reason strings
 * ***********************************************************************************************/

// Function to load the error strings into libcrypto 
ARDENT_RESULT ardent_set_openssl_reason_strings(void);

/* ************************************************************************************************
 * SUBSYSTEM initialization
 * ***********************************************************************************************/

// Initialize the logging subsystem; source in logging/ardent_logging.c */
ARDENT_RESULT ardent_logging_init(void* prov_ctx);

// Finalize the logging subsystem; called once during provider close; source in ardent_logging.c
void ardent_logging_fini(void);

// Initialize provider-owned seed sources and DRBG state.
ARDENT_SEEDING_CTX* ardent_seeding_new(void *prov_ctx);

// Finalize provider-owned seed sources and DRBG state.
void ardent_seeding_free(ARDENT_SEEDING_CTX *ctx);

// Initialize the debug subsystem; source in debug/ardent_debug_core.c
void ardent_debug_init(void);

// Initialize immutable debug control; source in debug/debug_core.c
void ardent_debug_control_init(void *prov_ctx);

// Finalize the debug subsystem; source in debug/ardent_debug_core.c
void ardent_debug_fini(void);

#ifdef __cplusplus
}
#endif
#endif /* ARDENT_INTERNAL_H */
