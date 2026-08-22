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

#include "kpep/kpep.h"

#if defined(KPEP_TRACE_DISABLED)

EXPORT_VISIBILITY_HIDDEN
void kpep_trace_init(void) {}

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
#include "internal/thread_arch.h"

#include "logging_utility.h"
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

static CRYPTO_MUTEX *trace_mutex = NULL;

static int trace_enabled = 0;
static FILE *trace_stream = NULL;
static uint64_t trace_start_us = 0;

static uint64_t kpep_trace_monotonic_us(void)
{
    return kpep_log_monotonic_us();
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

    kpep_log_report_error_once("TRACE ERROR", "%s", buf);
}

static void kpep_trace_lock(void)
{
	if (!trace_mutex)
		trace_mutex = ossl_crypto_mutex_new();
	if (trace_mutex)
		ossl_crypto_mutex_lock(trace_mutex);
}

static void kpep_trace_unlock(void)
{
	if (trace_mutex)
		ossl_crypto_mutex_unlock(trace_mutex);
}

static int kpep_trace_validate_filename(const char *path)
{
    return kpep_log_validate_filename(path);
}

static int kpep_trace_is_enabled_flag(const char *name)
{
    return kpep_log_is_enabled_flag(name);
}

static int kpep_trace_get_strict_mode(void)
{
	const char *value = getenv("KPEP_TRACE_STRICT");
	return value != NULL && value[0] != '\0' && strcmp(value, "1") == 0;
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

static int kpep_trace_touch_file(const char *path, FILE **out_stream)
{
    return kpep_log_touch_file(path, out_stream, "KPEP trace start");
}

EXPORT_VISIBILITY_HIDDEN
void kpep_trace_fini(void)
{
    if (trace_enabled && trace_stream) {
        fclose(trace_stream);
        trace_stream = NULL;
    }
    trace_enabled = 0;
}

EXPORT_VISIBILITY_HIDDEN
void kpep_trace_init(void) 
{
	const char *trace_env;
	char filename[PATH_MAX] = {0};
	FILE *opened_trace = NULL;

	// Flush last state; initialize new
	kpep_trace_fini();
	trace_stream = NULL;
	trace_enabled = 0;
	trace_start_us = kpep_trace_monotonic_us();

	// Read Environment Variables for trace flags
	kpep_trace_seed_enabled = kpep_trace_is_enabled_flag("KPEP_TRACE_SEED");
	kpep_trace_sink_enabled = kpep_trace_is_enabled_flag("KPEP_TRACE_SINK");
	kpep_trace_thread_enabled = kpep_trace_is_enabled_flag("KPEP_TRACE_THREAD");
	kpep_trace_strict_mode = kpep_trace_get_strict_mode();
	if (!kpep_trace_seed_enabled && !kpep_trace_sink_enabled && !kpep_trace_thread_enabled) {
		return;
	}

	// Process trace file name and validate it as best we can
	trace_env = getenv("KPEP_TRACE_FILE");
	if (!trace_env || trace_env[0] == '\0') {
		kpep_trace_report_error_once(KPEP_R_FILE_UNEXPECTED,
			"KPEP_TRACE_FILE is required to enable tracing; tracing disabled");
		kpep_trace_fini();
		return;
	}

	if (strlen(trace_env) >= sizeof(filename)) {
		kpep_trace_report_error_once(KPEP_R_FILE_UNEXPECTED,
			"KPEP_TRACE_FILE is too long; tracing disabled");
		kpep_trace_fini();
		return;
	}

	strncpy(filename, trace_env, sizeof(filename) - 1);
	filename[sizeof(filename) - 1] = '\0';

	if (!kpep_trace_touch_file(filename, &opened_trace)) {
		kpep_trace_report_error_once(KPEP_R_FILE_UNEXPECTED,
			"KPEP_TRACE_FILE '%s' is invalid or not writable; tracing disabled",
			filename);
		if (opened_trace) {
			fclose(opened_trace);
			opened_trace = NULL;
		}
		kpep_trace_fini();
		return;
	}

	// If we got here, we're open and ready for tracing
	trace_stream = opened_trace;
	trace_enabled = 1;
}

static void kpep_trace_write_v(const char *module,
						   const char *submodule,
						   const char *fmt,
						   va_list args)
{
	va_list copy;
	char *msg = NULL;
	char ts[32];
	uint64_t now_us;

	if (!fmt)
		return;

	if (!trace_enabled || trace_stream == NULL)
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

	kpep_trace_lock();

	now_us = kpep_trace_monotonic_us();
	if (now_us < trace_start_us)
		now_us = trace_start_us;
	snprintf(ts, sizeof(ts), "[%13llu]", (unsigned long long)(now_us - trace_start_us));

	if (submodule && submodule[0] != '\0')
		fprintf(trace_stream, "%s %-12s : %s : %s\n", ts, module ? module : "", submodule, msg);
	else
		fprintf(trace_stream, "%s %-12s : %s\n", ts, module ? module : "", msg);
	if (kpep_trace_strict_mode) {
		fflush(trace_stream);
		if (ferror(trace_stream)) {
			clearerr(trace_stream);
			trace_enabled = 0;
			kpep_trace_report_error_once(KPEP_R_FILE_UNEXPECTED,
				"TRACE ERROR: failed to write trace output");
		}
	}
	kpep_trace_unlock();
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