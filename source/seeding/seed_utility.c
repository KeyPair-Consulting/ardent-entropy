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

#include "kpep/kpep.h"
#include "seed_sources.h"

/* ************************************************************************************************
 * ***********************************************************************************************
 * Definitions, declarations, and context structure
 * ***********************************************************************************************
 * ***********************************************************************************************/

uint32_t seed_get_gather_sz(const SEED_STUB_INFO *info, size_t nbits)
{
    // Calculate gather size and floor to block size
    size_t gather_sz;
    gather_sz = (info->full_entropy)?nbits:(size_t) (nbits / info->entropy_per_bit);
    if (gather_sz < info->block_size)
        gather_sz = info->block_size;
    return (uint32_t) gather_sz;
}
