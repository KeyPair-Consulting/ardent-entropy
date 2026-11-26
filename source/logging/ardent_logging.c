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
/*
 * DEVLOPER'S NOTE:
 * There is a bizarre bug wherein the call to the init_fn of the first sink causes a SEGFAULT.
 * This happens because of ASLR (Address Space Layout Randomization).  This was determined because 
 * the code will SEGFAULT when run from the console, but will compelete normally when run under GDB.  
 * If you run "set disable-randomization off" in GDB before execution, the SEGFAULT will occur.
 * 
 * Further research yields that the first sink to be COMPILED (first in the CMakeLists.txt) is
 * always the one that fails, regardless of its startup order in the init() function here.
 * 
 * The solution that worked is:
 * 1) Create a dummy sink that does nothing.  Make sure it is compiled first
 * 2) Access each sink's init_fn() pointer BEFORE calling it; access by printing it to /dev/null
 * 
 * DO NOT CHANGE THIS UNLESS YOU THOROUGHLY REGRESSION TEST THE NEW CODE!
 */

#define __STDC_WANT_LIB_EXT2__ 1  // Define you want TR 24731-2:2010 extensions
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "internal/thread_arch.h"

#include "ardent/ardent.h"
#include "ardent/ardent_names.h"

/* ************************************************************************************************
 * ************************************************************************************************
 * DEFINITIONS
 * ************************************************************************************************
 * ***********************************************************************************************/

static const char* level_strings[] = { "FATAL", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG" };

typedef struct log_sink_st {
	const char           *name;
	const SINK_FUNCTIONS *fn;
} LOG_SINK;

#define MAX_SINK_COUNT 4
static LOG_SINK sinks[MAX_SINK_COUNT] = { 0 };

static unsigned int activate_syslog = 0;
static unsigned int activate_stderr = 0;
static unsigned int activate_extern = 0;

static CRYPTO_MUTEX *log_mutex = NULL;

static void ardent_log_lock(void)
{
	if (log_mutex == NULL)
		log_mutex = ossl_crypto_mutex_new();
	if (log_mutex)
		ossl_crypto_mutex_lock(log_mutex);
}

static void ardent_log_unlock(void)
{
	if (log_mutex)
		ossl_crypto_mutex_unlock(log_mutex);
}

/* ************************************************************************************************
 * ************************************************************************************************
 * "PUBLIC" functions
 * ************************************************************************************************
 * ***********************************************************************************************/

ARDENT_RESULT ardent_log_add_sink(const SINK_FUNCTIONS *funcs)
{
	size_t idx;

	if (ardent_trace_sink_enabled) {
		ardent_trace("ARDENT-SINK", __func__);
	}

	if (!funcs || 
		!funcs->init_fn ||
		!funcs->fini_fn ||
		!funcs->name_fn ||
		!funcs->level_fn ||
		!funcs->write_fn ||
		!funcs->write_data_fn) {
		return ARDENT_R_INVALID_ARG;
	}

	for (idx=0; idx<MAX_SINK_COUNT; ++idx) {
		if (sinks[idx].fn == NULL) {
			if (ardent_trace_sink_enabled) {
				ardent_trace_fmt("ARDENT-SINK", "Adding log sink '%s' to slot #%d", funcs->name_fn(), (int)idx);
			}
			sinks[idx].fn = funcs;
			sinks[idx].name = funcs->name_fn();
			break;
		}
	}
	if (idx == MAX_SINK_COUNT) {
		printf("ERROR: Could not attach log sink; no slots available\n");
		return ARDENT_R_NO_SLOTS;
	}

	return ARDENT_R_SUCCESS;
}

LogLevel read_log_level_string(const char *level)
{
	if (level) {
		if ((strcasecmp(level, "FATAL") == 0) || 
			(strcasecmp(level, "EMERG") == 0) ||
			(strcasecmp(level, "EMERGENCY") == 0))
			return LOG_LVL_FATAL;
		else if (strcasecmp(level, "ALERT") == 0)
			return LOG_LVL_ALERT;
		else if ((strcasecmp(level, "CRIT") == 0) || (strcasecmp(level, "CRITICAL") == 0))
			return LOG_LVL_CRIT;
		else if ((strcasecmp(level, "ERR") == 0) || (strcasecmp(level, "ERROR") == 0))
			return LOG_LVL_ERR;
		else if ((strcasecmp(level, "WARN") == 0) || (strcasecmp(level, "WARNING") == 0))
			return LOG_LVL_WARN;
		else if (strcasecmp(level, "NOTICE") == 0)
			return LOG_LVL_NOTICE;
		else if (strcasecmp(level, "INFO") == 0)
			return LOG_LVL_INFO;
		else if (strcasecmp(level, "DEBUG") == 0)
			return LOG_LVL_DEBUG;
	}
	return LOG_LVL_FATAL;
}

const char*  get_log_level_string(LogLevel level)
{
	if (LEVEL_IN_RANGE(level))
		return level_strings[level];
	else
		return "Requested level is out of range.";
}

static ARDENT_RESULT load_params_from_environment(void);
static ARDENT_RESULT load_params_from_openssl(void* prov_ctx);

extern const SINK_FUNCTIONS sink_dummy;
extern const SINK_FUNCTIONS sink_syslog;
extern const SINK_FUNCTIONS sink_stderr;
#ifndef ARDENT_DISABLE_EXTERNAL
extern const SINK_FUNCTIONS sink_extern;
#endif

EXPORT_VISIBILITY_HIDDEN
ARDENT_RESULT ardent_logging_init(void* prov_ctx) 
{
	ARDENT_RESULT rv = ARDENT_R_SUCCESS;
	FILE* devnull = NULL;

	if (ardent_trace_sink_enabled) {
		ardent_trace("ARDENT-SINK", __func__);
	}

	if (log_mutex == NULL)
		log_mutex = ossl_crypto_mutex_new();

	// Try to load configuration; pass all errors up
	rv = prov_ctx?load_params_from_openssl(prov_ctx)
	             :load_params_from_environment();
	if (rv)
		goto err;

	// BUGFIX: Pre-access the sink pointers to avoid bizarre SEGFAULT with ASLR relocation
#ifdef _WIN32
	devnull = fopen("NUL", "w");
#else
	devnull = fopen("/dev/null", "w");
#endif
	if (!devnull) {
		rv = ARDENT_R_LOG_BUGFIX_FAIL;
		goto err;
	}
	fprintf(devnull, "DUMMY : %p : %p\n", &sink_dummy,  sink_dummy.init_fn);
	fprintf(devnull, "SYSLOG: %p : %p\n", &sink_syslog, sink_syslog.init_fn);
	fprintf(devnull, "STDOUT: %p : %p\n", &sink_stderr, sink_stderr.init_fn);
#ifndef ARDENT_DISABLE_EXTERNAL
	fprintf(devnull, "EXTERN: %p : %p\n", &sink_extern, sink_extern.init_fn);
#endif
	fclose(devnull);

	// Attempt to activate each of the 3 known types
	if (activate_syslog) {
		rv = (sink_syslog.init_fn)(prov_ctx);
		if (rv == ARDENT_R_SUCCESS)
			rv = ardent_log_add_sink(&sink_syslog);
		if (rv != ARDENT_R_SUCCESS) {
			printf("ERROR: Log sink 'SYSLOG' could not load properly: %s\n", ardent_get_reason_string(rv));
			goto err;
		}
	}
	if (activate_stderr) {
		rv = sink_stderr.init_fn(prov_ctx);
		if (rv == ARDENT_R_SUCCESS)
			rv = ardent_log_add_sink(&sink_stderr);
		if (rv != ARDENT_R_SUCCESS) {
			printf("ERROR: Log sink 'STDERR' could not load properly: %s\n", ardent_get_reason_string(rv));
			goto err;
		}
	}
#ifndef ARDENT_DISABLE_EXTERNAL
	if (activate_extern) {
		rv = sink_extern.init_fn(prov_ctx);
		if (rv == ARDENT_R_SUCCESS)
			rv = ardent_log_add_sink(&sink_extern);
		if (rv != ARDENT_R_SUCCESS) {
			printf("ERROR: Log sink 'EXTERN' could not load properly: %s\n", ardent_get_reason_string(rv));
			goto err;
		}
	}
#endif

	rv = ARDENT_R_SUCCESS;

err:
	return rv;
}

EXPORT_VISIBILITY_HIDDEN
void ardent_logging_fini(void)
{
	size_t idx;

	if (ardent_trace_sink_enabled) {
		ardent_trace("ARDENT-SINK", __func__);
	}

	for (idx=0; idx<MAX_SINK_COUNT; ++idx) {
		if (sinks[idx].fn && sinks[idx].fn->fini_fn)
			sinks[idx].fn->fini_fn();
		sinks[idx].fn = NULL;
		sinks[idx].name = NULL;
	}

	return;
}

EXPORT_VISIBILITY_HIDDEN
void ardent_get_sink_descs(char *buffer)
{
	size_t idx;
	for (idx=0; idx<MAX_SINK_COUNT; ++idx) {
		if (!sinks[idx].fn) {
			break;
		}
		sprintf("  Name: %-12s Lvl: %-12s\n", 
				sinks[idx].name, 
				get_log_level_string(sinks[idx].fn->level_fn()));
	}
}

/* ************************************************************************************************
 * ************************************************************************************************
 * CONFIGURATION
 * ************************************************************************************************
 * ***********************************************************************************************/

#include "openssl/params.h"

static ARDENT_RESULT load_params_from_environment(void)
{
	char *dbgenv;

	dbgenv = getenv(ENV_LOG_SYSLOG_LEVEL);
	if (dbgenv != NULL) {
		activate_syslog = 1;
	}
	dbgenv = getenv(ENV_LOG_STDERR_LEVEL);
	if (dbgenv != NULL) {
		activate_stderr = 1;
	}
	dbgenv = getenv(ENV_LOG_EXTERN_LEVEL);
	if (dbgenv != NULL) {
		activate_extern = 1;
	}
	return ARDENT_R_SUCCESS;
}

static ARDENT_RESULT load_params_from_openssl(void* prov_ctx)
{
    const char *act_syslog = NULL;
    const char *act_stderr = NULL;
    const char *act_extern = NULL;

	OSSL_PARAM params[4], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        ARDENT_PROV_PARAM_LOG_SYSLOG_ACTIVATE,
        (char **) &act_syslog,
        sizeof(act_syslog));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        ARDENT_PROV_PARAM_LOG_STDERR_ACTIVATE,
        (char **) &act_stderr,
        sizeof(act_stderr));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        ARDENT_PROV_PARAM_LOG_EXTERN_ACTIVATE,
        (char **) &act_extern,
        sizeof(act_extern));
    *p = OSSL_PARAM_construct_end();

    if (!ardent_get_core_params(prov_ctx, params)) {
        return ARDENT_R_CONFIG_LOOKUP_FAILURE;
    }

	if (act_syslog)
    	activate_syslog = atoi(act_syslog);
	if (act_stderr)
		activate_stderr = atoi(act_stderr);
	if (act_extern)
		activate_extern = atoi(act_extern);

    return ARDENT_R_SUCCESS;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * LOG FUNCTIONS
 * ************************************************************************************************
 * ***********************************************************************************************/

void ardent_log(LogLevel level, const char* module, const char *fmt, ...) 
{
	size_t idx;
	va_list args;

	ardent_log_lock();
	for (idx=0; idx<MAX_SINK_COUNT; ++idx) {
		if (sinks[idx].fn && sinks[idx].fn->write_fn) {
			if (ardent_trace_sink_enabled) {
				ardent_trace_fmt("ARDENT-SINK", "Writing msg to sink '%s'.", sinks[idx].name);
			}
			va_start(args, fmt);
			sinks[idx].fn->write_fn(level, module, fmt, args);
			va_end(args);
		}
	}
	ardent_log_unlock();
}

void ardent_log_data(LogLevel level, const char* module, const char* label, 
					unsigned char *bytes, size_t bytes_len)
{
	size_t idx;

	ardent_log_lock();
	for (idx=0; idx<MAX_SINK_COUNT; ++idx) {
		if (sinks[idx].fn && sinks[idx].fn->write_data_fn) {
			if (ardent_trace_sink_enabled) {
				ardent_trace_fmt("ARDENT-SINK", "Writing data to sink '%s'.", sinks[idx].name);
			}
			sinks[idx].fn->write_data_fn(level, module, label, bytes, bytes_len);
		}
	}
	ardent_log_unlock();
}
