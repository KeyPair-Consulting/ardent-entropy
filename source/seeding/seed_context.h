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

#ifndef KPEP_SEED_CONTEXT_H
#define KPEP_SEED_CONTEXT_H
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STUB_NAME_LENGTH 32

/*
 * This definition is REQUIRED to be the first item in every seed_stud_source context variable.
 * This definition is used with the structure below to provide limited visibility into the
 * otherwise opaque context structures.
 */
#define COMMON_STUB_INFO             \
    char     name[STUB_NAME_LENGTH]; \
    uint32_t state;                  \
    uint32_t full_entropy;           \
    size_t   block_size;             \
    size_t   block_count;            \
    double   entropy_per_bit;        \
    uint8_t  idx;

/*
 * This structure is used to cast each opaque seed-source context structure so the 
 * async ring buffer can read the capabilities of each seed-source in order to make 
 * make use of this information common to all seed-sources.
 */
typedef struct {
    COMMON_STUB_INFO
} SEED_STUB_INFO;

#ifdef __cplusplus
}
#endif
#endif /* KPEP_SEED_CONTEXT_H */
