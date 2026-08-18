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

#include "kpep/kpep.h"
#include "kpep/kpep_names.h"

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

#ifdef TRACE_ENABLED
static CRYPTO_MUTEX *trace_mutex = NULL;

static FILE *trace_stream = NULL;
static int trace_initialized = 0;
static int trace_enabled = 1;
static int trace_file_mode = 0;
static int trace_error_reported = 0;
#endif

static void kpep_log_lock(void)
{
	if (log_mutex == NULL)
		log_mutex = ossl_crypto_mutex_new();
	if (log_mutex)
		ossl_crypto_mutex_lock(log_mutex);
}

static void kpep_log_unlock(void)
{
	if (log_mutex)
		ossl_crypto_mutex_unlock(log_mutex);
}

#ifdef TRACE_ENABLED
static void kpep_trace_report_error_once(const char *fmt, ...)
{
	va_list args;

	if (trace_error_reported)
		return;

	trace_error_reported = 1;
	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);
	fputc('\n', stdout);
	fflush(stdout);
}

static void kpep_trace_lock(void)
{
	if (trace_mutex == NULL)
		trace_mutex = ossl_crypto_mutex_new();
	if (trace_mutex)
		ossl_crypto_mutex_lock(trace_mutex);
}

static void kpep_trace_unlock(void)
{
	if (trace_mutex)
		ossl_crypto_mutex_unlock(trace_mutex);
}

static int kpep_trace_build_filename(char *buffer, size_t buffer_len)
{
	char ts[32] = {0};
	time_t now;
	struct tm t;

	now = time(NULL);
#if defined(_WIN32)
	if (localtime_s(&t, &now) != 0)
		return 0;
#else
	if (localtime_r(&now, &t) == NULL)
		return 0;
#endif

	if (strftime(ts, sizeof(ts), "%Y-%m-%d-%H-%M-%S", &t) == 0)
		return 0;

	if (snprintf(buffer, buffer_len, "kpmp_trace_%s.log", ts) <= 0)
		return 0;

	return 1;
}

static void kpep_trace_init(void)
{
	const char *trace_env;
	char filename[128] = {0};

	if (trace_initialized)
		return;

	trace_stream = stdout;
	trace_enabled = 1;
	trace_file_mode = 0;

	trace_env = getenv("KPEP_TRACE_FILE");
	if (trace_env && trace_env[0] != '\0') {
		trace_file_mode = 1;
		if (!kpep_trace_build_filename(filename, sizeof(filename))) {
			kpep_trace_report_error_once("TRACE ERROR: failed to build trace filename");
			trace_enabled = 0;
			trace_stream = NULL;
		} else {
			trace_stream = fopen(filename, "w");
			if (trace_stream == NULL) {
				kpep_trace_report_error_once("TRACE ERROR: failed to open trace file '%s'", filename);
				trace_enabled = 0;
				trace_stream = NULL;
			}
		}
	}

	trace_initialized = 1;
}

static void kpep_trace_write_v(const char *module,
						   const char *submodule,
						   const char *fmt,
						   va_list args)
{
	va_list copy;
	char *msg = NULL;
	FILE *out;

	if (!fmt)
		return;

	va_copy(copy, args);
	if (vasprintf(&msg, fmt, copy) < 0)
		msg = NULL;
	va_end(copy);

	if (!msg) {
		kpep_trace_report_error_once("TRACE ERROR: failed to format trace message");
		return;
	}

	kpep_trace_lock();
	if (!trace_initialized)
		kpep_trace_init();

	if (!trace_enabled || trace_stream == NULL) {
		kpep_trace_unlock();
		free(msg);
		return;
	}

	out = trace_stream;
	if (submodule && submodule[0] != '\0')
		fprintf(out, "%-12s : %s : %s\n", module ? module : "", submodule, msg);
	else
		fprintf(out, "%-12s : %s\n", module ? module : "", msg);

	fflush(out);
	if (ferror(out)) {
		clearerr(out);
		trace_enabled = 0;
		kpep_trace_report_error_once("TRACE ERROR: failed to write trace output");
	}

	kpep_trace_unlock();
	free(msg);
}
#endif

/* ************************************************************************************************
 * ************************************************************************************************
 * "PUBLIC" functions
 * ************************************************************************************************
 * ***********************************************************************************************/

KPEP_RESULT kpep_log_add_sink(const SINK_FUNCTIONS *funcs)
{
	size_t idx;

	#if defined (KPEP_TRACE_SINK)
	kpep_trace("KPEP-SINK", __func__);
    #endif

	if (!funcs || 
		!funcs->init_fn ||
		!funcs->fini_fn ||
		!funcs->name_fn ||
		!funcs->level_fn ||
		!funcs->write_fn ||
		!funcs->write_data_fn) {
		return KPEP_R_INVALID_ARG;
	}

	for (idx=0; idx<MAX_SINK_COUNT; ++idx) {
		if (sinks[idx].fn == NULL) {
			#if defined (KPEP_TRACE_SINK)
			kpep_trace_fmt("KPEP-SINK", "Adding log sink '%s' to slot #%d", funcs->name_fn(), (int)idx);
			#endif
			sinks[idx].fn = funcs;
			sinks[idx].name = funcs->name_fn();
			break;
		}
	}
	if (idx == MAX_SINK_COUNT) {
		printf("ERROR: Could not attach log sink; no slots available\n");
		return KPEP_R_LOG_NO_SINK_SLOTS;
	}

	return KPEP_R_SUCCESS;
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

static KPEP_RESULT load_params_from_environment(void);
static KPEP_RESULT load_params_from_openssl(void* prov_ctx);

extern const SINK_FUNCTIONS sink_dummy;
extern const SINK_FUNCTIONS sink_syslog;
extern const SINK_FUNCTIONS sink_stderr;
#ifndef KPEP_DISABLE_EXTERNAL
extern const SINK_FUNCTIONS sink_extern;
#endif

EXPORT_VISIBILITY_HIDDEN
KPEP_RESULT kpep_logging_init(void* prov_ctx) 
{
	KPEP_RESULT rv = KPEP_R_SUCCESS;
	FILE* devnull = NULL;

	#if defined (KPEP_TRACE_SINK)
	kpep_trace("KPEP-SINK", __func__);
    #endif

	if (log_mutex == NULL)
		log_mutex = ossl_crypto_mutex_new();
#ifdef TRACE_ENABLED
	if (trace_mutex == NULL)
		trace_mutex = ossl_crypto_mutex_new();
	kpep_trace_init();
#endif

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
		rv = KPEP_R_LOG_BUGFIX_FAIL;
		goto err;
	}
	fprintf(devnull, "DUMMY : %p : %p\n", &sink_dummy,  sink_dummy.init_fn);
	fprintf(devnull, "SYSLOG: %p : %p\n", &sink_syslog, sink_syslog.init_fn);
	fprintf(devnull, "STDOUT: %p : %p\n", &sink_stderr, sink_stderr.init_fn);
#ifndef KPEP_DISABLE_EXTERNAL
	fprintf(devnull, "EXTERN: %p : %p\n", &sink_extern, sink_extern.init_fn);
#endif
	fclose(devnull);

	// Attempt to activate each of the 3 known types
	if (activate_syslog) {
		rv = (sink_syslog.init_fn)(prov_ctx);
		if (rv == KPEP_R_SUCCESS)
			rv = kpep_log_add_sink(&sink_syslog);
		if (rv != KPEP_R_SUCCESS) {
			printf("ERROR: Log sink 'SYSLOG' could not load properly: %s\n", kpep_get_reason_string(rv));
			goto err;
		}
	}
	if (activate_stderr) {
		rv = sink_stderr.init_fn(prov_ctx);
		if (rv == KPEP_R_SUCCESS)
			rv = kpep_log_add_sink(&sink_stderr);
		if (rv != KPEP_R_SUCCESS) {
			printf("ERROR: Log sink 'STDERR' could not load properly: %s\n", kpep_get_reason_string(rv));
			goto err;
		}
	}
#ifndef KPEP_DISABLE_EXTERNAL
	if (activate_extern) {
		rv = sink_extern.init_fn(prov_ctx);
		if (rv == KPEP_R_SUCCESS)
			rv = kpep_log_add_sink(&sink_extern);
		if (rv != KPEP_R_SUCCESS) {
			printf("ERROR: Log sink 'EXTERN' could not load properly: %s\n", kpep_get_reason_string(rv));
			goto err;
		}
	}
#endif

	rv = KPEP_R_SUCCESS;

err:
	return rv;
}

EXPORT_VISIBILITY_HIDDEN
void kpep_logging_fini(void)
{
	size_t idx;

	#if defined (KPEP_TRACE_SINK)
	kpep_trace("KPEP-SINK", __func__);
    #endif

	for (idx=0; idx<MAX_SINK_COUNT; ++idx) {
		if (sinks[idx].fn && sinks[idx].fn->fini_fn)
			sinks[idx].fn->fini_fn();
		sinks[idx].fn = NULL;
		sinks[idx].name = NULL;
	}
#ifdef TRACE_ENABLED
	if (trace_file_mode && trace_stream) {
		fclose(trace_stream);
	}
	trace_stream = NULL;
	trace_initialized = 0;
	trace_enabled = 1;
	trace_file_mode = 0;
	trace_error_reported = 0;
	ossl_crypto_mutex_free(&trace_mutex);
	ossl_crypto_mutex_free(&log_mutex);
#endif

	return;
}

EXPORT_VISIBILITY_HIDDEN
void kpep_get_sink_descs(char *buffer)
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

static KPEP_RESULT load_params_from_environment(void)
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
	return KPEP_R_SUCCESS;
}

static KPEP_RESULT load_params_from_openssl(void* prov_ctx)
{
    const char *act_syslog = NULL;
    const char *act_stderr = NULL;
    const char *act_extern = NULL;

	OSSL_PARAM params[4], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        KPEP_PROV_PARAM_LOG_SYSLOG_ACTIVATE,
        (char **) &act_syslog,
        sizeof(act_syslog));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        KPEP_PROV_PARAM_LOG_STDERR_ACTIVATE,
        (char **) &act_stderr,
        sizeof(act_stderr));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        KPEP_PROV_PARAM_LOG_EXTERN_ACTIVATE,
        (char **) &act_extern,
        sizeof(act_extern));
    *p = OSSL_PARAM_construct_end();

    if (!kpep_get_core_params(prov_ctx, params)) {
        return KPEP_R_CONFIG_LOOKUP_FAILURE;
    }

	if (act_syslog)
    	activate_syslog = atoi(act_syslog);
	if (act_stderr)
		activate_stderr = atoi(act_stderr);
	if (act_extern)
		activate_extern = atoi(act_extern);

    return KPEP_R_SUCCESS;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * LOG FUNCTIONS
 * ************************************************************************************************
 * ***********************************************************************************************/

void kpep_log(LogLevel level, const char* module, const char *fmt, ...) 
{
	size_t idx;
	va_list args;

	kpep_log_lock();
	for (idx=0; idx<MAX_SINK_COUNT; ++idx) {
		if (sinks[idx].fn && sinks[idx].fn->write_fn) {
			#if defined (KPEP_TRACE_SINK)
			kpep_trace_fmt("KPEP-SINK", "Writing msg to sink '%s'.", sinks[idx].name);
			#endif
			va_start(args, fmt);
			sinks[idx].fn->write_fn(level, module, fmt, args);
			va_end(args);
		}
	}
	kpep_log_unlock();
}

void kpep_log_data(LogLevel level, const char* module, const char* label, 
					unsigned char *bytes, size_t bytes_len)
{
	size_t idx;

	kpep_log_lock();
	for (idx=0; idx<MAX_SINK_COUNT; ++idx) {
		if (sinks[idx].fn && sinks[idx].fn->write_data_fn) {
			#if defined (KPEP_TRACE_SINK)
			kpep_trace_fmt("KPEP-SINK", "Writing data to sink '%s'.", sinks[idx].name);
			#endif
			sinks[idx].fn->write_data_fn(level, module, label, bytes, bytes_len);
		}
	}
	kpep_log_unlock();
}

#ifdef TRACE_ENABLED
void kpep_trace(const char* module, const char* msg)
{
	kpep_trace_sub(module, NULL, msg);
}

void kpep_trace_sub(const char* module, const char* submodule, const char* msg)
{
	if (!msg)
		msg = "";
	kpep_trace_sub_fmt(module, submodule, "%s", msg);
}

void kpep_trace_fmt(const char* module, const char* fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	kpep_trace_write_v(module, NULL, fmt, args);
	va_end(args);
}

void kpep_trace_sub_fmt(const char* module, const char* submodule, const char* fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	kpep_trace_write_v(module, submodule, fmt, args);
	va_end(args);
}
#endif
