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

#ifndef KPEP_CPUINFO_H
#define KPEP_CPUINFO_H
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum cpu_type_e {
    CPU_UNKNOWN = 0,
    CPU_INTEL,
    CPU_AMD,
    //CPU_ARM  /* NOT IMPLEMENTED */
} CPU_TYPE;

typedef struct {
    uint32_t EAX;
    uint32_t EBX;
    uint32_t ECX;
    uint32_t EDX;
} CPUIDinfo;

extern void get_cpuid(CPUIDinfo *info, const uint32_t func, const uint32_t subfunc);

extern int  check_is_amd(void);
extern int  check_is_intel(void);

extern int  check_aesni_support(void);
extern int  check_rdrand_support(void);
extern int  check_rdseed_support(void);

#ifdef __cplusplus
}
#endif
#endif /* KPEP_CPUINFO_H */