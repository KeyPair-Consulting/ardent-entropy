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

 /* ***********************************************************************************************
 * RDRAND/RDSEED Implementation
 * Based on:
 * https://github.com/dj-on-github/rdrand_stdint
 * which is clearly based on:
 * https://www.intel.com/content/dam/develop/external/us/en/documents/drng-software-implementation-guide-2-1-185467.pdf
 *
 * 1) No license text is required, but we acknowledge here in source
 * 2) Unnecessary functions and features have been removed
 * 3) Functions have been renamed
 * ***********************************************************************************************/

#include <stdint.h>
#include <immintrin.h> // For _mm_pause

#include "kpep/kpep.h"
#include "rdcpu_toolbox.h"

/**********************************************/
/* Gathers 64 bits of entropy through RDRAND  */
/*   Writes that entropy to *therand.         */
/*   Returns 1 on success, or 0 on underflow  */
/**********************************************/

EXPORT_VISIBILITY_HIDDEN
int rdrand64_step(uint64_t *therand)
{
    uint64_t foo;
    int cf_error_status;
    asm("\n\
        rdrand %%rax;\n\
        mov $1,%%edx;\n\
        cmovae %%rax,%%rdx;\n\
        mov %%edx,%1;\n\
        mov %%rax, %0;":"=r"(foo),"=r"(cf_error_status)::"%rax","%rdx");
    *therand = foo;
    return cf_error_status;
}

/**********************************************/
/* Gathers 64 bits of entropy through RDSEED  */
/*   Writes that entropy to *therand.         */
/*   Returns 1 on success, or 0 on underflow  */
/**********************************************/

EXPORT_VISIBILITY_HIDDEN
int rdseed64_step(uint64_t *therand)
{
    uint64_t foo;
    int cf_error_status;
    asm("\n\
        rdseed %%rax;\n\
        mov $1,%%edx;\n\
        cmovae %%rax,%%rdx;\n\
        mov %%edx,%1;\n\
        mov %%rax, %0;":"=r"(foo),"=r"(cf_error_status)::"%rax","%rdx");
    *therand = foo;
    return cf_error_status;
}

/****************************************************************/
/* Uses RdRand to acquire a block of n 64 bit random numbers    */
/*   Writes that entropy to (unsigned long long *)dest[0+].     */
/*   Will retry up to retry_limit times                         */
/*   Returns 1 on success, or 0 on underflow                    */
/****************************************************************/

EXPORT_VISIBILITY_HIDDEN
int rdrand_get_n_uint64_retry(uint32_t n, uint32_t retry_limit, uint64_t *dest)
{
    int success;
    uint32_t count;
    uint32_t i;

    for (i=0; i<n; i++) {
        count = 0;
        do {
            success = rdrand64_step(dest);
            // As per Intel recommendation (Section 5.3.1.2, pg. 32):
            // https://www.intel.com/content/dam/develop/external/us/en/documents/drng-software-implementation-guide-2-1-185467.pdf
            _mm_pause();  
        } while((success == 0) && (count++ < retry_limit));
        if (success == 0) 
            return 0;
        dest = &(dest[1]);
    }
    return 1; 
}

/****************************************************************/
/* Uses RdSeed to acquire a block of n 64 bit random numbers    */
/*   Writes that entropy to (unsigned long long *)dest[0+].     */
/*   Will retry up to retry_limit times                         */
/*   Returns 1 on success, or 0 on underflow                    */
/****************************************************************/

EXPORT_VISIBILITY_HIDDEN
int rdseed_get_n_uint64_retry(uint32_t n, uint32_t retry_limit, uint64_t *dest)
{
    int success;
    uint32_t count;
    uint32_t i;

    for (i=0; i<n; i++) {
        count = 0;
        do {
            success = rdseed64_step(dest);
            // As per Intel recommendation (Section 5.3.1.2, pg. 32):
            // https://www.intel.com/content/dam/develop/external/us/en/documents/drng-software-implementation-guide-2-1-185467.pdf
            _mm_pause();  
        } while((success == 0) && (count++ < retry_limit));
        if (success == 0) 
            return 0;
        dest = &(dest[1]);
    }
    return 1; 
}

/****************************************************************/
/* Uses RdRand to acquire a block of random bytes               */
/*   Uses RdRand64 to optimize speed                            */
/*   Writes that entropy to (unsigned int *)dest[0+].           */
/*   Internally will retry up to 10 times on underflow.         */
/*   Returns 1 on success, 0 on failure                         */
/****************************************************************/

EXPORT_VISIBILITY_HIDDEN
int rdrand_get_bytes_step(unsigned int n, unsigned char *dest, unsigned int retry_count)
{
    unsigned char *start;
    unsigned char *residualstart;
    uint64_t *blockstart;
    unsigned int count;
    unsigned int residual;
    unsigned int startlen;
    uint64_t i;
    uint64_t temprand;
    unsigned int length;

    /* Compute the address of the first 64 bit aligned block in the destination buffer */
    start = dest;
    if (((uint64_t)start % (uint64_t)8) == 0) {
        blockstart = (uint64_t *)start;
        count = n;
        startlen = 0;
    }
    else {
        blockstart = (uint64_t *)(((uint64_t)start & ~(uint64_t)7)+(uint64_t)8);
        count = n - (8 - (unsigned int)((uint64_t)start % 8));
        startlen = (unsigned int)((uint64_t)blockstart - (uint64_t)start);
    }

    /* Compute the number of 64 bit blocks and the remaining number of bytes */
    residual = count % 8;
    length = count >> 3;
    if (residual != 0) {
        residualstart = (unsigned char *)(blockstart + length);
    }

    /* Get a temporary random number for use in the residuals. Failout if retry fails */
    if (startlen > 0) {
        if (rdrand_get_n_uint64_retry(1, retry_count, (void *)&temprand) == 0) 
            return 0;
    }

    /* populate the starting misaligned block */
    for (i = 0; i<startlen; i++) {
        start[i] = (unsigned char)(temprand & 0xff);
        temprand = temprand >> 8;
    }

    /* populate the central aligned block. Fail out if retry fails */
    if (rdrand_get_n_uint64_retry(length, retry_count, (void *)(blockstart)) == 0) 
        return 0;

    /* populate the final misaligned block */
    if (residual > 0) {
        if (rdrand_get_n_uint64_retry(1, retry_count, (void *)&temprand) == 0) 
            return 0;
        for (i = 0; i<residual; i++) {
            residualstart[i] = (unsigned char)(temprand & 0xff);
            temprand = temprand >> 8;
        }
    }

    return 1;
}

/****************************************************************/
/* Uses RdSeed to acquire a block of random bytes               */
/*   Uses RdSeed64 which is not optimized for speed...?         */
/*   Writes that entropy to (unsigned int *)dest[0+].           */
/*   Internally will retry up to 10 times on underflow.         */
/*   Returns 1 on success, 0 on failure                         */
/****************************************************************/

EXPORT_VISIBILITY_HIDDEN
int rdseed_get_bytes_step(unsigned int n, unsigned char *dest, unsigned int retry_count)
{
    unsigned char *start;
    unsigned char *residualstart;
    uint64_t *blockstart;
    unsigned int count;
    unsigned int residual;
    unsigned int startlen;
    uint64_t i;
    uint64_t temprand;
    unsigned int length;

    /* Compute the address of the first 64 bit aligned block in the destination buffer */
    start = dest;
    if (((uint64_t)start % (uint64_t)8) == 0) {
        blockstart = (uint64_t *)start;
        count = n;
        startlen = 0;
    }
    else {
        blockstart = (uint64_t *)(((uint64_t)start & ~(uint64_t)7)+(uint64_t)8);
        count = n - (8 - (unsigned int)((uint64_t)start % 8));
        startlen = (unsigned int)((uint64_t)blockstart - (uint64_t)start);
    }

    /* Compute the number of 64 bit blocks and the remaining number of bytes */
    residual = count % 8;
    length = count >> 3;
    if (residual != 0) {
        residualstart = (unsigned char *)(blockstart + length);
    }

    /* Get a temporary random number for use in the residuals. Failout if retry fails. */
    if (startlen > 0) {
        if (rdseed_get_n_uint64_retry(1, retry_count, (void *)&temprand) == 0) 
            return 0;
    }

    /* populate the starting misaligned block */
    for (i = 0; i<startlen; i++) {
        start[i] = (unsigned char)(temprand & 0xff);
        temprand = temprand >> 8;
    }

    /* populate the central aligned block. Fail out if retry fails */
    if (rdseed_get_n_uint64_retry(length, retry_count, (void *)(blockstart)) == 0) 
        return 0;

    /* populate the final misaligned block */
    if (residual > 0) {
        if (rdseed_get_n_uint64_retry(1, retry_count, (void *)&temprand) == 0) 
            return 0;
        for (i = 0; i<residual; i++) {
            residualstart[i] = (unsigned char)(temprand & 0xff);
            temprand = temprand >> 8;
        }
    }

    return 1;
}
