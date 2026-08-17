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

#ifndef KPEP_INTERNAL_H
#define KPEP_INTERNAL_H
#pragma once

#include "kpep/kpep.h"  // For KPEP_RESULT

#ifdef __cplusplus
extern "C" {
#endif

/* ************************************************************************************************
 * SEED-SOURCE descriptions and Mode
 * ***********************************************************************************************/

// Get a multi-line string containing a description of all the seed sources, one per line; source in kpep_seeding.c
const char* kpep_seeding_get_description(void);

// Get a boolean (0/1) whether entropy restrive counting (Method #1) is enabled
int kpep_seeding_get_restricted_mode(void);

/* ************************************************************************************************
 * ERROR Reason strings
 * ***********************************************************************************************/

// Function to load the error strings into libcrypto 
KPEP_RESULT kpep_set_openssl_reason_strings(void);

/* ************************************************************************************************
 * SUBSYSTEM initialization
 * ***********************************************************************************************/

// Initialize the logging subsystem; source in logging/kpep_logging.c */
KPEP_RESULT kpep_logging_init(void* prov_ctx);

// Finalize the logging subsystem; called once during provider close; source in kpep_logging.c
void kpep_logging_fini(void);

// Initialize the "singleton"; called once during provider init; source in kpep_seeding.c
KPEP_RESULT kpep_seeding_init(void* prov_ctx);

// Finalize the "singleton"; called once during provider close; source in kpep_seeding.c
void kpep_seeding_fini(void);

#ifdef __cplusplus
}
#endif
#endif /* KPEP_INTERNAL_H */
