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

/* Windows implementation is functional, not strict. */

#define __STDC_WANT_LIB_EXT2__ 1  // Define you want TR 24731-2:2010 extensions
#define _GNU_SOURCE

#include "ardent/ardent.h"

#if defined(ARDENT_TRACE_DISABLED)

EXPORT_VISIBILITY_HIDDEN
void ardent_trace_init(const ARDENT_DEBUG_TRACE_CONFIG *config) { (void)config; }

EXPORT_VISIBILITY_HIDDEN
void ardent_trace_fini(void) {}

#if 0
void ardent_trace(const char* module, const char* msg) { (void)module; (void)msg; }
void ardent_trace_sub(const char* module, const char* submodule, const char* msg) { (void)module; (void)submodule; (void)msg; }
void ardent_trace_fmt(const char* module, const char* fmt, ...) { (void)module; (void)fmt; }
void ardent_trace_sub_fmt(const char* module, const char* submodule, const char* fmt, ...) { (void)module; (void)submodule; (void)fmt; }
#endif

#else

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <limits.h>

#if defined(OPENSSL_SYS_WINDOWS) || defined(WINDOWS)
# include <windows.h>
#endif

#include "internal/e_os.h"

#include "debug_utility.h"
#include "debug_core.h"
#include "ardent/ardent_names.h"

/* ************************************************************************************************
 * ************************************************************************************************
 * DEFINITIONS
 * ************************************************************************************************
 * ***********************************************************************************************/

int ardent_trace_seed_enabled = 0;
int ardent_trace_sink_enabled = 0;
int ardent_trace_thread_enabled = 0;
int ardent_trace_lazy_write = 0;

static int trace_enabled = 0;
static ARDENT_DEBUG_SINK *trace_sink = NULL;
static uint64_t trace_start_us = 0;

static uint64_t ardent_trace_monotonic_us(void)
{
	return ardent_debug_monotonic_us();
}

EXPORT_VISIBILITY_HIDDEN
void ardent_trace_fini(void)
{
	ardent_debug_sink_release(&trace_sink);
    trace_enabled = 0;
	trace_start_us = 0;
	ardent_trace_seed_enabled = 0;
	ardent_trace_sink_enabled = 0;
	ardent_trace_thread_enabled = 0;
	ardent_trace_lazy_write = 0;
}

EXPORT_VISIBILITY_HIDDEN
void ardent_trace_init(const ARDENT_DEBUG_TRACE_CONFIG *config)
{
	// Flush last state; initialize new
	ardent_trace_fini();
	if (!config)
		return;

	trace_enabled = 0;
	trace_start_us = ardent_trace_monotonic_us();

	ardent_trace_seed_enabled = config->seed;
	ardent_trace_sink_enabled = config->sink;
	ardent_trace_thread_enabled = config->thread;
	ardent_trace_lazy_write = config->lazy_write;
	if (!ardent_trace_seed_enabled && !ardent_trace_sink_enabled && !ardent_trace_thread_enabled) {
		return;
	}

	if (!config->file || config->file[0] == '\0') {
		ardent_debug_report_error_once("TRACE ERROR",
			"trace file is required to enable tracing; tracing disabled");
		return;
	}

	trace_sink = ardent_debug_sink_acquire(config->file, "TRACE ERROR", "trace.file");
	if (!trace_sink) {
		return;
	}

	// If we got here, we're open and ready for tracing
	trace_enabled = 1;
}

static void ardent_trace_write_v(const char *module,
						   const char *submodule,
						   const char *fmt,
						   va_list args)
{
	va_list copy;
	char msg[512];
	char line[1024];
	char ts[32];
	uint64_t now_us;
	int n;

	if (!fmt)
		return;

	if (!trace_enabled || trace_sink == NULL)
		return;

	va_copy(copy, args);
	n = vsnprintf(msg, sizeof(msg), fmt, copy);
	va_end(copy);

	if (n < 0) {
		ardent_debug_report_error_once("TRACE ERROR", "failed to format trace message");
		return;
	}

	now_us = ardent_trace_monotonic_us();
	if (now_us < trace_start_us)
		now_us = trace_start_us;
	snprintf(ts, sizeof(ts), "[%13llu]", (unsigned long long)(now_us - trace_start_us));

	if (submodule && submodule[0] != '\0')
		snprintf(line, sizeof(line), "%s %-12s : %s : %s\n", ts, module ? module : "", submodule, msg);
	else
		snprintf(line, sizeof(line), "%s %-12s : %s\n", ts, module ? module : "", msg);

	if (!ardent_debug_sink_write(trace_sink, line, !ardent_trace_lazy_write)) {
		trace_enabled = 0;
		ardent_debug_report_error_once("TRACE ERROR", "failed to write trace output");
	}
}

void ardent_trace_fmt(const char* module, const char* fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ardent_trace_write_v(module, NULL, fmt, args);
	va_end(args);
}

void ardent_trace_sub_fmt(const char* module, const char* submodule, const char* fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ardent_trace_write_v(module, submodule, fmt, args);
	va_end(args);
}

void ardent_trace_sub(const char* module, const char* submodule, const char* msg)
{
	if (!msg)
		msg = "";
	ardent_trace_sub_fmt(module, submodule, "%s", msg);
}

void ardent_trace(const char* module, const char* msg)
{
	if (!msg)
		msg = "";
	ardent_trace_sub_fmt(module, NULL, "%s", msg);
}

#endif