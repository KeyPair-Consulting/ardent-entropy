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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <string.h>

#include <openssl/err.h>

#include "kpep/kpep.h"

/* ************************************************************************************************
 * ************************************************************************************************
 * REASON STRINGS
 * ************************************************************************************************
 * ***********************************************************************************************/

/* THESE MUST APPEAR IN THE SAME ORDER AS THEIR ERROR CODES */
static ERR_STRING_DATA reasons[] = {
	// 101
	{.string = "Failed to allocate memory (Malloc Failure)"},
	{.string = "Function argument is NULL"},
	{.string = "Function argument is invalid"},
	{.string = "Generate error retrieving entropy"},
	{.string = "Forcibly generated error to support FIPS OpTesting"},
	// 106
	{.string = "Failed to load an external resource"},
	{.string = "Failed to initialize the internal SHA2 algorithm"},
	{.string = "KDF failed operation"},
	{.string = "There are no slots left to add a logging sink"},
	{.string = "The logging BugFix work-around has failed"},
	// 111
	{.string = "RESERVED 111"},
	{.string = "RESERVED 112"},
	{.string = "Seed source has not been instantiated"},
	{.string = "Seed source is in an error state"},
	{.string = "Seed source not supported by this CPU"},
	// 116
	{.string = "Seed buffer is too small"},
	{.string = "No seed source slots available for configured source"},
	{.string = "RESERVED 118"},
	{.string = "RESERVED 119"},
	{.string = "RESERVED 120"},
	// 121
	{.string = "DRBG is in an invalid state"},
	{.string = "DRBG has insufficient entropy"},
	{.string = "DRBG request too large"},
	{.string = "DRBG has no seed source"},
	{.string = "DRBG failed startup"},
	// 126
	{.string = "File not valid"},
	{.string = "Failed to open a file"},
	{.string = "Bad permissions"},
	{.string = "File not found"},
	{.string = "Unexpected error accessing file"},
	// 131
	{.string = "EOF error reading seed from file"},
	{.string = "File error reading seed from file"},
	{.string = "Failure looking up a configuration parameter"},
	{.string = "A configuration parameter was missing"},
	{.string = "A configuration parameter was invalid or could not be converted to the proper format"},
	// 136
	{.string = "Ring buffer requested size is not valid"},
	{.string = "Ring buffer size is not a power of two"},
	{.string = "Ring buffer is full"},
	{.string = "Ring buffer is empty"},
	{.string = "RESERVED 140"},
	// 141
	{.string = "Thread not ready"},
	{.string = "Thread failed startup"},
	{.string = "Synchronization lock failed to be acquired"},
	{.string = "Seed control subsystem failure (no available entropy sources)"},
	{.string = "RESERVED 145"},
	// 146
	{.string = "Seed source is not ready"},
	{.string = "Seed source error 1"},
	{.string = "Seed source error 2"},
	{.string = "Seed source error 3"},
	{.string = "Seed source generated a FATAL error"},
};

 /* ************************************************************************************************
 * ************************************************************************************************
 * ERROR FUNCTIONS
 * ************************************************************************************************
 * ***********************************************************************************************/

/* Library ID assigned by OpenSSL at runtime for error handling/lookup */
EXPORT_VISIBILITY_HIDDEN
int ERR_LIB_KPEP = 0;

EXPORT_VISIBILITY_HIDDEN
int kpep_set_openssl_reason_strings(void)
{
	int idx;

	// Get our library ID
	ERR_LIB_KPEP = ERR_get_next_error_library();
	if (!ERR_LIB_KPEP) {
		printf("Failed to secure a library ID for error handling\n");
		return 0;
	}

	// Fill in our packed identifier based on the assigned Library ID
	for (idx=0; idx<KPEP_R_COUNT; ++idx) {
		reasons[idx].error = ERR_PACK(ERR_LIB_KPEP, 0, KPEP_R_START+idx);
	}

	// Load the reasopn strings into libcrypto
	if (!ERR_load_strings(ERR_LIB_KPEP, reasons)) {
		printf("Failed to load the error reason strings into OpenSSL\n");
		return 0;
	}

	return 1;
}

EXPORT_VISIBILITY_DEFAULT
const char* kpep_get_reason_string(KPEP_RESULT result, const char *module)
{
	if ((result < KPEP_R_START) || (result > KPEP_R_END))  {
		LOG_FORMATTED_ERROR(module, "Error number out of range (got %3d, expected %3d..%3d).", result, KPEP_R_START, KPEP_R_END);
		return "Error number out of range";
	}
	return reasons[result-KPEP_R_START].string;
}

