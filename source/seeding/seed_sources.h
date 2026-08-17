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

extern const STUB_FUNCTIONS stub_jitter;
extern const STUB_FUNCTIONS stub_rdseed;
extern const STUB_FUNCTIONS stub_rdrand;
extern const STUB_FUNCTIONS stub_osrand;
extern const STUB_FUNCTIONS stub_extern;

typedef struct seed_source_def_st {
    const char *desc;
    const char *prefix;
    uint32_t    force_hardware;
    uint32_t    idx;
    const STUB_FUNCTIONS *stub_fn;
} SEED_SOURCE_DEF;

static const SEED_SOURCE_DEF seed_source_defs[] = {
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

#ifdef __cplusplus
}
#endif
#endif /* KPEP_SEED_SOURCE_H */