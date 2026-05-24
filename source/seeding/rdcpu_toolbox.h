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

#ifndef KPEP_RDCPU_TOOLBOX_H
#define KPEP_RDCPU_TOOLBOX_H
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


/* ***********************************************************************************************
 * ***********************************************************************************************
 * RDRAND/RDSEED Implementation
 * Based on:
 * https://github.com/dj-on-github/rdrand_stdint
 * 
 * 1) No license text is required, but acknowledgement, at least here in code, is only respectful
 * 2) Unnecessary functions and features have been removed
 * 3) Functions have been renamed
 * ***********************************************************************************************
 * ***********************************************************************************************/

/**********************************************/
/* Gathers 64 bits of entropy through RDRAND  */
/*   Writes that entropy to *therand.         */
/*   Returns 1 on success, or 0 on underflow  */
/**********************************************/

int rdrand64_step(uint64_t *therand);

/**********************************************/
/* Gathers 64 bits of entropy through RDSEED  */
/*   Writes that entropy to *therand.         */
/*   Returns 1 on success, or 0 on underflow  */
/**********************************************/

int rdseed64_step(uint64_t *therand);

/****************************************************************/
/* Uses RdRand to acquire a block of n 64 bit random numbers    */
/*   Writes that entropy to (unsigned long long *)dest[0+].     */
/*   Will retry up to retry_limit times                         */
/*   Returns 1 on success, or 0 on underflow                    */
/****************************************************************/

int rdrand_get_n_uint64_retry(uint32_t n, uint32_t retry_limit, uint64_t *dest);

/****************************************************************/
/* Uses RdSeed to acquire a block of n 64 bit random numbers    */
/*   Writes that entropy to (unsigned long long *)dest[0+].     */
/*   Will retry up to retry_limit times                         */
/*   Returns 1 on success, or 0 on underflow                    */
/****************************************************************/

int rdseed_get_n_uint64_retry(uint32_t n, uint32_t retry_limit, uint64_t *dest);

/****************************************************************/
/* Uses RdRand to acquire a block of random bytes               */
/*   Uses RdRand64 to optimize speed                            */
/*   Writes that entropy to (unsigned int *)dest[0+].           */
/*   Internally will retry up to 10 times on underflow.         */
/*   Returns 1 on success, 0 on failure                         */
/****************************************************************/

int rdrand_get_bytes_step(unsigned int n, unsigned char *dest);

/****************************************************************/
/* Uses RdSeed to acquire a block of random bytes               */
/*   Uses RdSeed64 which is not optimized for speed...?         */
/*   Writes that entropy to (unsigned int *)dest[0+].           */
/*   Internally will retry up to 10 times on underflow.         */
/*   Returns 1 on success, 0 on failure                         */
/****************************************************************/

int rdseed_get_bytes_step(unsigned int n, unsigned char *dest);

#ifdef __cplusplus
}
#endif
#endif /* KPEP_RDCPU_TOOLBOX_H */
