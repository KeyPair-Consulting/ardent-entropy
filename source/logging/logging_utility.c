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

#define __STDC_WANT_LIB_EXT2__ 1
#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
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

/* ************************************************************************************************
 * ************************************************************************************************
 * SHARED FILE / ENV UTILITY FUNCTIONS
 * ************************************************************************************************
 * ***********************************************************************************************/

int kpep_log_validate_filename(const char *path)
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

int kpep_log_is_enabled_flag(const char *name)
{
    const char *value = getenv(name);
    return value != NULL && value[0] != '\0' &&
           strcmp(value, "0") != 0 &&
           strcmp(value, "false") != 0 &&
           strcmp(value, "FALSE") != 0;
}

uint32_t kpep_log_parse_u32_env(const char *value)
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

void kpep_log_report_error_once(const char *tag, const char *fmt, ...)
{
    static const char *last_tag = NULL;
    static const char *last_fmt = NULL;
    va_list args;
    char buf[512];
    int n;

    if (last_tag && last_fmt && strcmp(last_tag, tag) == 0 && strcmp(last_fmt, fmt) == 0)
        return;

    last_tag = tag;
    last_fmt = fmt;

    va_start(args, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (n < 0)
        return;
    if (n >= (int)sizeof(buf))
        buf[sizeof(buf) - 1] = '\0';

    fprintf(stderr, "%s: %s\n", tag ? tag : "LOG ERROR", buf);
}

uint64_t kpep_log_monotonic_us(void)
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

int kpep_log_touch_file(const char *path, FILE **out_stream, const char *banner)
{
    FILE *fp;
    char stamp[64] = {0};
    time_t now;
    struct tm t;
    int rc;

    if (!kpep_log_validate_filename(path))
        return 0;

    fp = fopen(path, "a");
    if (!fp)
        return 0;

    now = time(NULL);
#if defined(OPENSSL_SYS_WINDOWS) || defined(WINDOWS)
    if (localtime_s(&t, &now) != 0) {
        fclose(fp);
        return 0;
    }
#else
    if (localtime_r(&now, &t) == NULL) {
        fclose(fp);
        return 0;
    }
#endif

    if (strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &t) == 0) {
        fclose(fp);
        return 0;
    }

    if (banner && banner[0] != '\0')
        rc = fprintf(fp, "\n=== %s %s ===\n", banner, stamp);
    else
        rc = fprintf(fp, "\n=== KPEP runtime log %s ===\n", stamp);

    if (rc < 0 || fflush(fp) != 0) {
        fclose(fp);
        return 0;
    }

    *out_stream = fp;
    return 1;
}
