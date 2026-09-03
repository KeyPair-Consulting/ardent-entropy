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
int kpep_trace_strict_mode = 0;

static int trace_enabled = 0;
static KPEP_DEBUG_SINK *trace_sink = NULL;
static uint64_t trace_start_us = 0;

static uint64_t kpep_trace_monotonic_us(void)
{
	return kpep_debug_monotonic_us();
}

static void kpep_trace_report_error_once(KPEP_RESULT kpep_errnum, const char *fmt, ...)
{
    static KPEP_RESULT last_reported = 0;
    va_list args;
    char buf[512];
    int n;

    if (last_reported == kpep_errnum)
        return;
    last_reported = kpep_errnum;

    va_start(args, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (n < 0)
        return;

    if (n >= (int)sizeof(buf))
        buf[sizeof(buf) - 1] = '\0';

    kpep_debug_report_error_once("TRACE ERROR", "%s", buf);
}

static int kpep_trace_get_realtime_timespec(struct timespec *ts)
{
#if defined(OPENSSL_SYS_WINDOWS) || defined(WINDOWS)
	FILETIME ft;
	ULONGLONG value;
	SYSTEMTIME st;
	struct tm tmv;
	TIME_ZONE_INFORMATION tz;
	long bias;

	if (!ts)
		return -1;

	GetSystemTimeAsFileTime(&ft);
	value = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
	value -= 116444736000000000ULL;
	ts->tv_sec = (time_t)(value / 10000000ULL);
	ts->tv_nsec = (long)((value % 10000000ULL) * 100ULL);

	GetLocalTime(&st);
	memset(&tmv, 0, sizeof(tmv));
	tmv.tm_year = st.wYear - 1900;
	tmv.tm_mon = st.wMonth - 1;
	tmv.tm_mday = st.wDay;
	tmv.tm_hour = st.wHour;
	tmv.tm_min = st.wMinute;
	tmv.tm_sec = st.wSecond;

	if (GetTimeZoneInformation(&tz) != TIME_ZONE_ID_INVALID) {
		bias = (long)tz.Bias * 60;
		if (tz.StandardDate.wMonth != 0)
			bias = (long)tz.Bias * 60;
		if (bias > 0)
			ts->tv_sec -= bias;
		else
			ts->tv_sec += (-bias);
	}
	return 0;
#else
	return clock_gettime(CLOCK_REALTIME, ts);
#endif
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
	kpep_trace_strict_mode = 0;
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
	kpep_trace_strict_mode = config->strict;
	if (!kpep_trace_seed_enabled && !kpep_trace_sink_enabled && !kpep_trace_thread_enabled) {
		return;
	}

	if (!config->file || config->file[0] == '\0') {
		kpep_trace_report_error_once(KPEP_R_FILE_UNEXPECTED,
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
	char *line = NULL;
	char *msg = NULL;
	char ts[32];
	uint64_t now_us;

	if (!fmt)
		return;

	if (!trace_enabled || trace_sink == NULL)
		return;

	va_copy(copy, args);
	if (vasprintf(&msg, fmt, copy) < 0)
		msg = NULL;
	va_end(copy);

	if (!msg) {
		kpep_trace_report_error_once(KPEP_R_FILE_UNEXPECTED,
			"TRACE ERROR: failed to format trace message");
		return;
	}

	now_us = kpep_trace_monotonic_us();
	if (now_us < trace_start_us)
		now_us = trace_start_us;
	snprintf(ts, sizeof(ts), "[%13llu]", (unsigned long long)(now_us - trace_start_us));

	if (submodule && submodule[0] != '\0')
		asprintf(&line, "%s %-12s : %s : %s\n", ts, module ? module : "", submodule, msg);
	else
		asprintf(&line, "%s %-12s : %s\n", ts, module ? module : "", msg);

	if (!line) {
		kpep_trace_report_error_once(KPEP_R_FILE_UNEXPECTED,
			"TRACE ERROR: failed to format trace output");
		free(msg);
		return;
	}

	if (!kpep_debug_sink_write(trace_sink, line, kpep_trace_strict_mode)) {
		trace_enabled = 0;
		kpep_trace_report_error_once(KPEP_R_FILE_UNEXPECTED,
			"TRACE ERROR: failed to write trace output");
	}
	free(line);
	free(msg);
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