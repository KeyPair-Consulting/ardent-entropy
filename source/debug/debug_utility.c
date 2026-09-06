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

#define __STDC_WANT_LIB_EXT2__ 1
#define _GNU_SOURCE

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>

#if defined(OPENSSL_SYS_WINDOWS) || defined(WINDOWS)
# include <windows.h>
#endif

#include "kpep/kpep.h"

#include "openssl/conf.h"
#include "openssl/err.h"

#include "debug_utility.h"

/* ************************************************************************************************
 * ************************************************************************************************
 * SHARED FILE / ENV UTILITY FUNCTIONS
 * ************************************************************************************************
 * ***********************************************************************************************/

static void kpep_debug_set_error_text(char *buf, size_t buf_len, const char *fmt, ...)
{
    va_list args;

    if (!buf || buf_len == 0)
        return;

    va_start(args, fmt);
    vsnprintf(buf, buf_len, fmt, args);
    va_end(args);
    buf[buf_len - 1] = '\0';
}

static void kpep_debug_get_os_error(char *buf, size_t buf_len)
{
    if (!buf || buf_len == 0)
        return;

#if defined(OPENSSL_SYS_WINDOWS) || defined(WINDOWS)
    {
        DWORD err = GetLastError();
        DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
        DWORD len = FormatMessageA(flags, NULL, err, 0, buf, (DWORD)buf_len, NULL);

        if (len == 0) {
            kpep_debug_set_error_text(buf, buf_len, "system error %lu", (unsigned long)err);
            return;
        }

        while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n')) {
            buf[len - 1] = '\0';
            --len;
        }
    }
#else
    kpep_debug_set_error_text(buf, buf_len, "%s", strerror(errno));
#endif
}

static int kpep_debug_write_banner(FILE *stream,
                                   const char *banner,
                                   char *errbuf,
                                   size_t errbuf_len)
{
    char stamp[64] = {0};
    time_t now;
    struct tm utc_tm;
    int rc;

    if (!stream)
        return 0;

    now = time(NULL);
#if defined(OPENSSL_SYS_WINDOWS) || defined(WINDOWS)
    if (gmtime_s(&utc_tm, &now) != 0) {
#else
    if (gmtime_r(&now, &utc_tm) == NULL) {
#endif
        kpep_debug_set_error_text(errbuf, errbuf_len, "failed to format UTC timestamp");
        return 0;
    }

    if (strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &utc_tm) == 0) {
        kpep_debug_set_error_text(errbuf, errbuf_len, "failed to format UTC timestamp");
        return 0;
    }

    rc = fprintf(stream, "\n=== %s === %s UTC ===\n",
                 banner ? banner : "KPEP Debug Output",
                 stamp);
    if (rc < 0 || fflush(stream) != 0) {
        kpep_debug_get_os_error(errbuf, errbuf_len);
        return 0;
    }

    return 1;
}

int kpep_debug_validate_filename(const char *path)
{
    struct stat st;
    const char *p;

    if (!path || path[0] == '\0')
        return 0;

    for (p = path; *p != '\0'; ++p) {
        if (*p == '\n' || *p == '\r' || *p == '\t')
            return 0;
    }

    if (strcmp(path, ".") == 0 || strcmp(path, "..") == 0)
        return 0;

    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
        return 0;

    return 1;
}

int kpep_debug_is_enabled_flag(const char *name)
{
    const char *value = getenv(name);
    return value != NULL && strcmp(value, "1") == 0;
}

int kpep_debug_is_stream_name(const char *name, FILE **out_stream)
{
    if (out_stream)
        *out_stream = NULL;

    if (!name)
        return 0;

    if (strcmp(name, "stdout") == 0) {
        if (out_stream)
            *out_stream = stdout;
        return 1;
    }

    if (strcmp(name, "stderr") == 0) {
        if (out_stream)
            *out_stream = stderr;
        return 1;
    }

    return 0;
}

int kpep_debug_parse_bool(const char *value, int *out)
{
    if (!value || !out)
        return 0;
    if (strcmp(value, "0") == 0) {
        *out = 0;
        return 1;
    }
    if (strcmp(value, "1") == 0) {
        *out = 1;
        return 1;
    }
    return 0;
}

uint32_t kpep_debug_parse_u32_env(const char *value)
{
    char *end = NULL;
    unsigned long parsed;

    if (!value || value[0] == '\0')
        return 0;

    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed > UINT32_MAX)
        return 0;

    return (uint32_t)parsed;
}

int kpep_debug_parse_interval(const char *value, uint32_t *out)
{
    uint32_t interval;

    if (!value || !out)
        return 0;

    interval = kpep_debug_parse_u32_env(value);
    if (interval == 0 && strcmp(value, "0") != 0)
        return 0;

    *out = interval;
    return 1;
}

void kpep_debug_report_error_once(const char *tag, const char *fmt, ...)
{
    static char last_tag[64] = {0};
    static char last_msg[512] = {0};
    va_list args;
    char buf[512];
    int n;

    va_start(args, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (n < 0)
        return;
    if (n >= (int)sizeof(buf))
        buf[sizeof(buf) - 1] = '\0';

    if (strcmp(last_tag, tag ? tag : "") == 0 && strcmp(last_msg, buf) == 0)
        return;

    strncpy(last_tag, tag ? tag : "", sizeof(last_tag) - 1);
    last_tag[sizeof(last_tag) - 1] = '\0';
    strncpy(last_msg, buf, sizeof(last_msg) - 1);
    last_msg[sizeof(last_msg) - 1] = '\0';

    fprintf(stderr, "%s: %s\n", tag ? tag : "LOG ERROR", buf);
}

uint64_t kpep_debug_monotonic_us(void)
{
#if defined(OPENSSL_SYS_WINDOWS) || defined(WINDOWS)
    LARGE_INTEGER freq;
    LARGE_INTEGER count;
    uint64_t elapsed_us;

    if (QueryPerformanceFrequency(&freq) && QueryPerformanceCounter(&count)) {
        elapsed_us = (uint64_t)((count.QuadPart * 1000000ULL) / freq.QuadPart);
        return elapsed_us;
    }

    {
        FILETIME ft;
        ULONGLONG value;
        GetSystemTimeAsFileTime(&ft);
        value = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        value -= 116444736000000000ULL;
        return (uint64_t)(value / 10ULL);
    }
#else
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return ((uint64_t)ts.tv_sec * 1000000ULL) + ((uint64_t)ts.tv_nsec / 1000ULL);

    {
        struct timeval tv;
        if (gettimeofday(&tv, NULL) == 0)
            return ((uint64_t)tv.tv_sec * 1000000ULL) + ((uint64_t)tv.tv_usec);
    }
    return 0;
#endif
}

int kpep_debug_open_output(const char *name,
                           const char *banner,
                           FILE **out_stream,
                           int *out_owned,
                           char *errbuf,
                           size_t errbuf_len)
{
    FILE *fp = NULL;

    if (out_stream)
        *out_stream = NULL;
    if (out_owned)
        *out_owned = 0;
    if (errbuf && errbuf_len > 0)
        errbuf[0] = '\0';

    if (!name || name[0] == '\0') {
        kpep_debug_set_error_text(errbuf, errbuf_len, "empty stream name");
        return 0;
    }

    if (kpep_debug_is_stream_name(name, &fp)) {
        if (!kpep_debug_write_banner(fp, banner, errbuf, errbuf_len))
            return 0;
        if (out_stream)
            *out_stream = fp;
        return 1;
    }

    if (!kpep_debug_validate_filename(name)) {
        kpep_debug_set_error_text(errbuf, errbuf_len, "invalid path");
        return 0;
    }

    fp = fopen(name, "a");
    if (!fp) {
        kpep_debug_get_os_error(errbuf, errbuf_len);
        return 0;
    }

    if (!kpep_debug_write_banner(fp, banner, errbuf, errbuf_len)) {
        fclose(fp);
        return 0;
    }

    if (out_stream)
        *out_stream = fp;
    if (out_owned)
        *out_owned = 1;
    return 1;
}
