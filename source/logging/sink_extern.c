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

 #include "kpep/kpep.h"

/*  External libraries can be disabled by compilation flags */
#ifdef KPEP_DISABLE_EXTERNAL
EXPORT_VISIBILITY_HIDDEN
SINK_FUNCTIONS sink_extern = {
	.init_fn = NULL,
	.fini_fn = NULL,
	.name_fn = NULL,
	.level_fn = NULL,
	.write_fn = NULL,
	.write_data_fn = NULL
};
#else

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

#include <dlfcn.h>

#include "kpep/kpep_names.h"

static LogLevel current_log_level = LOG_LVL_FATAL;

// Handle to shared object
static void* hnd = NULL;

// Pointer to functions array
static SINK_FUNCTIONS *ext_sink = NULL;

// Pointer to filepath
static const char *filepath = NULL;
static const char *functions = NULL;

static const char* filename = NULL;

/* ************************************************************************************************
 * ************************************************************************************************
 * CONFIGURATION
 * ************************************************************************************************
 * ***********************************************************************************************/

#include "openssl/params.h"

static KPEP_RESULT load_params_from_environment(void)
{
	char *dbgenv;

	dbgenv = getenv(ENV_LOG_EXTERN_LEVEL);
	if (dbgenv != NULL) {
		current_log_level = read_log_level_string(dbgenv);
	}
	dbgenv = getenv(ENV_LOG_EXTERN_FILEPATH);
	if (dbgenv != NULL) {
		filepath = dbgenv;
	}
	dbgenv = getenv(ENV_LOG_EXTERN_FUNCTIONS);
	if (dbgenv != NULL) {
		functions = dbgenv;
	}
	return KPEP_R_SUCCESS;
}

static KPEP_RESULT load_params_from_openssl(void* prov_ctx)
{
	const char *level_str = NULL;
	const char *filepath_str = NULL;
	const char *functions_str = NULL;
	OSSL_PARAM params[4], *p = params;

	// Set parameters for lookup
	*p++ = OSSL_PARAM_construct_utf8_ptr(
		KPEP_PROV_PARAM_LOG_EXTERN_FILEPATH,
		(char **) &filepath_str,
		sizeof(filepath_str));	
	*p++ = OSSL_PARAM_construct_utf8_ptr(
		KPEP_PROV_PARAM_LOG_EXTERN_FUNCTIONS,
		(char **) &functions_str,
		sizeof(functions_str));
	*p++ = OSSL_PARAM_construct_utf8_ptr(
		KPEP_PROV_PARAM_LOG_EXTERN_LEVEL,
		(char **) &level_str,
		sizeof(level_str));
	*p = OSSL_PARAM_construct_end();

	// Lookup
	if (!kpep_get_core_params(prov_ctx, params)) {
        return KPEP_R_CONFIG_LOOKUP_FAILURE;
	}

	if (filepath_str)
		filepath = filepath_str;
	if (functions_str)
		functions = functions_str;
	if (level_str)
		current_log_level = read_log_level_string(level_str);
	else 
		current_log_level = LOG_LVL_ERR;

	return KPEP_R_SUCCESS;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * SINK Functions
 * ************************************************************************************************
 * ***********************************************************************************************/
 
static KPEP_RESULT init_log_extern(void* prov_ctx)
{
	KPEP_RESULT rv = KPEP_R_SUCCESS;

	#if defined (KPEP_TRACE_SINK)
    printf("*** -SINK: %s\n", __func__);
    #endif
	rv = prov_ctx?load_params_from_openssl(prov_ctx)
	             :load_params_from_environment();
	if (rv) return rv;

	// Initialize source
	if (!filepath || !functions) {
		rv = KPEP_R_NULL_ARG;
		goto err;
	}
	hnd = dlopen(filepath, RTLD_LAZY | RTLD_LOCAL);
	if (!hnd) {
		printf("DLOPEN error: %s\n", dlerror());
		rv = KPEP_R_EXTERN_LOAD_FAILURE;
		goto err;
	}
	ext_sink = (SINK_FUNCTIONS*) dlsym(hnd, functions);
	if (!ext_sink) {
		printf("DLSYM error: %s\n", dlerror());
		rv = KPEP_R_EXTERN_LOAD_FAILURE;
		goto err;
	}

	// Get the name
	(filename = strrchr(filepath, '/')) ? ++filename : (filename = filepath);

	// Call new on the stub
	rv = ext_sink->init_fn(prov_ctx);
	if (rv) {
		printf("ERROR: Failed to initialize external log sink: %s\n", kpep_get_reason_string(rv));
		goto err;
	}

	rv = KPEP_R_SUCCESS;

err:
	if (rv && hnd) {  // Error and handle?
		dlclose(hnd);
		hnd = NULL;
	}
	return rv;
}

static void fini_log_extern(void)
{
	#if defined (KPEP_TRACE_SINK)
    printf("*** -SINK: %s\n", __func__);
    #endif
	ext_sink->fini_fn();
	return;
}

static const char* get_name_extern(void)
{
	return (const char*) filename;
}

static LogLevel get_level_extern(void)
{
	return ext_sink->level_fn();
}

static void write_log_extern(LogLevel level, const char* module, const char* fmt, va_list args)
{
	#if defined (KPEP_TRACE_SINK)
    printf("*** -SINK: %s\n", __func__);
    #endif
	ext_sink->write_fn(level, module, fmt, args);
	return;
}

static void write_log_data_extern(LogLevel level, const char* module, const char* label, unsigned char *bytes, size_t bytes_len)
{
	#if defined (KPEP_TRACE_SINK)
    printf("*** -SINK: %s\n", __func__);
    #endif
	ext_sink->write_data_fn(level, module, label, bytes, bytes_len);
	return;
}

EXPORT_VISIBILITY_HIDDEN
SINK_FUNCTIONS sink_extern = {
	.init_fn = &init_log_extern,
	.fini_fn = &fini_log_extern,
	.name_fn = &get_name_extern,
	.level_fn = &get_level_extern,
	.write_fn = &write_log_extern,
	.write_data_fn = &write_log_data_extern
};

#endif /* KPEP_DISABLE_EXTERNAL */