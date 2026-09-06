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

#include "kpep/kpep.h"

#if defined(KPEP_TRACE_DISABLED)

EXPORT_VISIBILITY_HIDDEN
void kpep_trace_init(const KPEP_DEBUG_TRACE_CONFIG *config) { (void)config; }

EXPORT_VISIBILITY_HIDDEN
void kpep_trace_fini(void) {}

#if 0
void kpep_trace(const char* module, const char* msg) { (void)module; (void)msg; }
void kpep_trace_sub(const char* module, const char* submodule, const char* msg) { (void)module; (void)submodule; (void)msg; }
void kpep_trace_fmt(const char* module, const char* fmt, ...) { (void)module; (void)fmt; }
void kpep_trace_sub_fmt(const char* module, const char* submodule, const char* fmt, ...) { (void)module; (void)submodule; (void)fmt; }
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
#include "kpep/kpep_names.h"

/* ************************************************************************************************
 * ************************************************************************************************
 * DEFINITIONS
 * ************************************************************************************************
 * ***********************************************************************************************/

int kpep_trace_seed_enabled = 0;
int kpep_trace_sink_enabled = 0;
int kpep_trace_thread_enabled = 0;
int kpep_trace_lazy_write = 0;

static int trace_enabled = 0;
static KPEP_DEBUG_SINK *trace_sink = NULL;
static uint64_t trace_start_us = 0;

static uint64_t kpep_trace_monotonic_us(void)
{
	return kpep_debug_monotonic_us();
}

EXPORT_VISIBILITY_HIDDEN
void kpep_trace_fini(void)
{
	kpep_debug_sink_release(&trace_sink);
    trace_enabled = 0;
	trace_start_us = 0;
	kpep_trace_seed_enabled = 0;
	kpep_trace_sink_enabled = 0;
	kpep_trace_thread_enabled = 0;
	kpep_trace_lazy_write = 0;
}

EXPORT_VISIBILITY_HIDDEN
void kpep_trace_init(const KPEP_DEBUG_TRACE_CONFIG *config)
{
	// Flush last state; initialize new
	kpep_trace_fini();
	if (!config)
		return;

	trace_enabled = 0;
	trace_start_us = kpep_trace_monotonic_us();

	kpep_trace_seed_enabled = config->seed;
	kpep_trace_sink_enabled = config->sink;
	kpep_trace_thread_enabled = config->thread;
	kpep_trace_lazy_write = config->lazy_write;
	if (!kpep_trace_seed_enabled && !kpep_trace_sink_enabled && !kpep_trace_thread_enabled) {
		return;
	}

	if (!config->file || config->file[0] == '\0') {
		kpep_debug_report_error_once("TRACE ERROR",
			"trace file is required to enable tracing; tracing disabled");
		return;
	}

	trace_sink = kpep_debug_sink_acquire(config->file, "TRACE ERROR", "trace.file");
	if (!trace_sink) {
		return;
	}

	// If we got here, we're open and ready for tracing
	trace_enabled = 1;
}

static void kpep_trace_write_v(const char *module,
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
		kpep_debug_report_error_once("TRACE ERROR", "failed to format trace message");
		return;
	}

	now_us = kpep_trace_monotonic_us();
	if (now_us < trace_start_us)
		now_us = trace_start_us;
	snprintf(ts, sizeof(ts), "[%13llu]", (unsigned long long)(now_us - trace_start_us));

	if (submodule && submodule[0] != '\0')
		snprintf(line, sizeof(line), "%s %-12s : %s : %s\n", ts, module ? module : "", submodule, msg);
	else
		snprintf(line, sizeof(line), "%s %-12s : %s\n", ts, module ? module : "", msg);

	if (!kpep_debug_sink_write(trace_sink, line, !kpep_trace_lazy_write)) {
		trace_enabled = 0;
		kpep_debug_report_error_once("TRACE ERROR", "failed to write trace output");
	}
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

void kpep_trace_sub(const char* module, const char* submodule, const char* msg)
{
	if (!msg)
		msg = "";
	kpep_trace_sub_fmt(module, submodule, "%s", msg);
}

void kpep_trace(const char* module, const char* msg)
{
	if (!msg)
		msg = "";
	kpep_trace_sub_fmt(module, NULL, "%s", msg);
}

#endif