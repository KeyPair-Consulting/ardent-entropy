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

#include "kpep/kpep.h"
#include "kpep/kpep_names.h"

#ifndef TRACE_ENABLED
EXPORT_VISIBILITY_HIDDEN
KPEP_RESULT kpep_trace_init(void* prov_ctx) { return KPEP_R_SUCCESS; }
void kpep_trace_fini(void) {}
#else

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "internal/thread_arch.h"

/* ************************************************************************************************
 * ************************************************************************************************
 * DEFINITIONS
 * ************************************************************************************************
 * ***********************************************************************************************/

static CRYPTO_MUTEX *trace_mutex = NULL;

static FILE *trace_stream = NULL;
static int trace_initialized = 0;
static int trace_enabled = 1;
static int trace_file_mode = 0;
static int trace_error_reported = 0;

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

EXPORT_VISIBILITY_HIDDEN
KPEP_RESULT kpep_trace_init(void* prov_ctx) 
{
	const char *trace_env;
	char filename[128] = {0};

	if (trace_initialized)
		return KPEP_R_SUCCESS;

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
	return KPEP_R_SUCCESS;
}

EXPORT_VISIBILITY_HIDDEN
void kpep_trace_fini(void)
{
	if (trace_file_mode && trace_stream) {
		fclose(trace_stream);
		trace_stream = NULL;
	}
	trace_initialized = 0;
	trace_enabled = 0;
	trace_file_mode = 0;
	trace_error_reported = 0;
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