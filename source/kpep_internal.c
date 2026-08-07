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
#include <ctype.h>
#include <string.h>

#include "kpep/kpep.h"
#include "kpep_internal.h"

/* ************************************************************************************************
 * ************************************************************************************************
 * GENERAL UTILITIES
 * ************************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_DEFAULT
void  kpep_free(void* ptr)
{
	if (!ptr)
		return;
	free(ptr);
}

EXPORT_VISIBILITY_DEFAULT
void  kpep_zeroize(void* ptr, size_t size)
{
	if (!ptr)
		return;
	memset(ptr, 0, size);
}

EXPORT_VISIBILITY_DEFAULT
void  kpep_cleanse(void* ptr, size_t size)
{
    kpep_zeroize(ptr, size);
    kpep_free(ptr);
}

EXPORT_VISIBILITY_DEFAULT
void* kpep_zalloc(size_t size)
{
    uint8_t *buffer = NULL;
    if ((size > 0) && (buffer = malloc(size)) != NULL) {
        memset(buffer, 0, size);
    }
    return buffer;
}

// Stores the trimmed input string into the given output buffer, which must be
// large enough to store the result.  If it is too small, the output is truncated.
// https://stackoverflow.com/questions/122616/how-do-i-trim-leading-trailing-whitespace-in-a-standard-way
EXPORT_VISIBILITY_DEFAULT
size_t kpep_trimwhitespace(char *out, size_t len, const char *str)
{
	const char *end;
	size_t out_size;

	if (len == 0)
		return 0;

	// Trim leading space
	while (isspace((unsigned char)*str)) str++;

	// All spaces?
	if (*str == 0) {
    	*out = 0;
    	return 0;
	}

	// Trim trailing space
	end = str + strlen(str) - 1;
	while(end > str && isspace((unsigned char)*end)) end--;
	end++;

  	// Set output size to minimum of trimmed string length and buffer size minus 1
	out_size = ((size_t) (end - str)) < len-1 ? (size_t) (end - str) : len-1;

	// Copy trimmed string and add null terminator
	memcpy(out, str, out_size);
	out[out_size] = 0;

	return out_size;
}

