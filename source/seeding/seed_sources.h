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

#ifndef KPEP_SEED_SOURCE_H
#define KPEP_SEED_SOURCE_H
#pragma once

#include <stdint.h>

#include "kpep/kpep_names.h"
#include "kpep/kpep_seed_stub.h"

#ifdef __cplusplus
extern "C" {
#endif

// Function collections defined in the stub source files
extern const STUB_FUNCTIONS stub_jitter;
extern const STUB_FUNCTIONS stub_rdseed;
extern const STUB_FUNCTIONS stub_rdrand;
extern const STUB_FUNCTIONS stub_osrand;
extern const STUB_FUNCTIONS stub_extern;

// Package of information for each seed source
typedef struct seed_source_def_st {
    const char *desc;
    const char *prefix;
    uint32_t    force_hardware;
    uint32_t    idx;
    const STUB_FUNCTIONS *stub_fn;
} SEED_SOURCE_DEF;

// All seed sources are defined here, with their associated stub function collections and parameters
static SEED_SOURCE_DEF seed_source_defs[] = {
    { "jitter",  KPEP_PROV_PARAM_SEED_JITTER, 0, 0, &stub_jitter },
    { "rdseed",  KPEP_PROV_PARAM_SEED_RDSEED, 1, 0, &stub_rdseed },
    { "rdrand",  KPEP_PROV_PARAM_SEED_RDRAND, 1, 0, &stub_rdrand },
    { "osrand1", KPEP_PROV_PARAM_SEED_OSRAND, 0, 1, &stub_osrand },
    { "osrand2", KPEP_PROV_PARAM_SEED_OSRAND, 0, 2, &stub_osrand },
    { "osrand3", KPEP_PROV_PARAM_SEED_OSRAND, 0, 3, &stub_osrand },
    { "osrand4", KPEP_PROV_PARAM_SEED_OSRAND, 0, 4, &stub_osrand },
    { "extern1", KPEP_PROV_PARAM_SEED_EXTERN, 0, 1, &stub_extern },
    { "extern2", KPEP_PROV_PARAM_SEED_EXTERN, 0, 2, &stub_extern },
    { "extern3", KPEP_PROV_PARAM_SEED_EXTERN, 0, 3, &stub_extern },
    { "extern4", KPEP_PROV_PARAM_SEED_EXTERN, 0, 4, &stub_extern },
    { NULL, NULL, 0, 0, NULL }
};

#define STUB_NAME_LENGTH 32

/*
 * This definition is REQUIRED to be the first item in every seed_stud_source context variable.
 * This definition is used with the structure below to provide limited visibility into the
 * otherwise opaque context structures.
 */
#define COMMON_STUB_INFO             \
    char     name[STUB_NAME_LENGTH]; \
    uint32_t idx;                    \
    uint32_t state;                  \
    uint32_t full_entropy;           \
    uint32_t block_size;             \
    uint32_t block_count;            \
    double   entropy_per_bit;

/*
 * This structure is used to cast each opaque seed-source context structure so the 
 * async ring buffer can read the capabilities of each seed-source in order to make 
 * make use of this information common to all seed-sources.
 */
typedef struct {
    COMMON_STUB_INFO
} SEED_STUB_INFO;

static inline
uint32_t seed_get_gather_sz(const SEED_STUB_INFO *info, size_t nbits)
{
    // Calculate gather size and floor to block size
    size_t gather_sz;
    gather_sz = (info->full_entropy)?nbits:(size_t) (nbits / info->entropy_per_bit);
    if (gather_sz < info->block_size)
        gather_sz = info->block_size;
    return (uint32_t) gather_sz;
}

#ifdef __cplusplus
}
#endif
#endif /* KPEP_SEED_SOURCE_H */
