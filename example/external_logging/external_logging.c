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

#define __STDC_WANT_LIB_EXT2__ 1  // Define you want TR 24731-2:2010 extensions
#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>

#include "kpep/kpep.h"
#include "kpep/kpep_names.h"

static const char alloc_msg[] = "Memory allocation error writing log entry";

static LogLevel current_log_level = LOG_LVL_FATAL;

static int my_custom_int = 0;

/* ************************************************************************************************
 * ************************************************************************************************
 * CONFIGURATION
 * ************************************************************************************************
 * ***********************************************************************************************/

#include "openssl/params.h"

static KPEP_RESULT load_params_from_environment(void)
{
	char *dbgenv;

	dbgenv = getenv("EXTERNAL_LOGGING_LEVEL");
	if (dbgenv != NULL) {
		current_log_level = read_log_level_string(dbgenv);
	}
	return KPEP_R_SUCCESS;
}

static KPEP_RESULT load_params_from_openssl(void* prov_ctx)
{
	// OpenSSL parameters must be read initially as a string.
	// Create one for each configuration option
	const char *level_str = NULL;
	const char *custom_str = NULL;

	// Create parameter array
	OSSL_PARAM params[3], *p = params;
	*p++ = OSSL_PARAM_construct_utf8_ptr(
		_PROV_PARAM_LOG_EXTERN_LEVEL,
		(char **) &level_str,
		sizeof(level_str));
	*p++ = OSSL_PARAM_construct_utf8_ptr(
		"logging.extern.custom-int",  // Parameters must use dashes '-' not underscores '_'
		(char **) &custom_str,
		sizeof(custom_str));
	*p = OSSL_PARAM_construct_end();

	// Retrieve the parameters from 'kpepmodule.cnf'
	if (!kpep_get_core_params(prov_ctx, params))
		return KPEP_R_CONFIG_LOOKUP_FAILURE;

	// This parameter must be present
	if (level_str)
		current_log_level = read_log_level_string(level_str);
	else
		return KPEP_R_NULL_ARG;

	// It's OK if this key isn't present -- it's already defaulted to zero
	if (custom_str)
		my_custom_int = atoi(custom_str);

	return KPEP_R_SUCCESS;
}
 
/* ************************************************************************************************
 * ************************************************************************************************
 * SINK Functions
 * ************************************************************************************************
 * ***********************************************************************************************/
 
static KPEP_RESULT init_log_example(void* prov_ctx)
{
	KPEP_RESULT rv = KPEP_R_SUCCESS;
	
	rv = prov_ctx?load_params_from_openssl(prov_ctx)
	             :load_params_from_environment();
	if (rv) return rv;
	
	// Initialize data structures based on configuration settings
	my_custom_int = !!my_custom_int;  // Force to 0/1 boolean

	return rv;
}

static void fini_log_example(void)
{
	return; // Nothing to do
}

static const char* get_name_example(void)
{
	return "EXAMPLE";
}

static LogLevel get_level_example(void)
{
	return current_log_level;
}

static void write_log_example(LogLevel level, const char* module, const char* fmt, va_list args)
{
	char *msg;

	if (level > current_log_level)
        return;
	if (vasprintf(&msg, fmt, args) < 0)
		msg = (char *)alloc_msg;
	fprintf(stderr, "%s%s%s\n", module?module:"", module?": ":"", msg);
	if (msg != alloc_msg)
		free(msg);
}

static void write_log_data_example(LogLevel level, const char* module, const char* label, unsigned char *bytes, size_t bytes_len)
{
	char *msg;
	size_t idx, i;

	idx =  14 + (bytes_len*2);  // 14 chars for formatting and EOL
	idx += module?strlen(module):0;
	idx += label?strlen(label):0;
	msg = kpep_zalloc(idx);
	if (!msg)
		return;
	if (module) {
		sprintf(msg, "%s: ", module);
	}
	idx = strlen(msg);
	sprintf(msg+idx, "%s [%04lu] : ", label, bytes_len);
	if (bytes_len > 32) {
		// Long buffers
		for (i=0, idx=strlen(msg); i<16; ++i, idx += 2) {
			sprintf(msg+idx, "%02X", bytes[i]);
		}
		sprintf(msg+idx, "...");
		for (i=bytes_len-16, idx=strlen(msg); i<bytes_len; ++i, idx += 2) {
			sprintf(msg+idx, "%02X", bytes[i]);
		}
	}
	else {
		// Short buffers
		for (i=0, idx=strlen(msg); i<bytes_len; ++i, idx += 2) {
			sprintf(msg+idx, "%02X", bytes[i]);
		}
	}
	fprintf(stderr, "%s\n", msg);  // EOL because this is stderr and we need to advance the cursor
	kpep_free(msg);
    return;
}

SINK_FUNCTIONS sink_example = {
	.init_fn = &init_log_example,
	.fini_fn = &fini_log_example,
	.name_fn = &get_name_example,
	.level_fn = &get_level_example,
	.write_fn = &write_log_example,
	.write_data_fn = &write_log_data_example
};

