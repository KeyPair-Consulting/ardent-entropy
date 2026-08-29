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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "internal/thread_arch.h"

#include "logging_utility.h"
#include "kpep/kpep_names.h"
#include "../seeding/seed_sources.h"

/* ************************************************************************************************
 * ************************************************************************************************
 * DEFINITIONS
 * ************************************************************************************************
 * ***********************************************************************************************/

// Globally available enable flag
int kpep_profile_enabled = 0;
int kpep_profile_each_sample = 0;

// Mutex to protect access to the profile stream and related state
static CRYPTO_MUTEX *profile_mutex = NULL;

// File stream used for writing profile data
static FILE *profile_stream = NULL;
static int profile_stream_owned = 0;

// Reset period used by the profile subsystem, in the same style as trace startup
static uint32_t reset_interval = 0;

static void kpep_profile_report_error_once(const char *fmt, ...)
{
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

    kpep_log_report_error_once("PROFILE ERROR", "%s", buf);
}

static int kpep_profile_validate_filename(const char *path)
{
    return kpep_log_validate_filename(path);
}

static int kpep_profile_touch_file(const char *path, FILE **out_stream)
{
    return kpep_log_touch_file(path, out_stream, "KPEP profile start");
}

static void kpep_profile_close_stream(void)
{
    if (profile_stream) {
        if (profile_stream_owned)
            fclose(profile_stream);
        else
            fflush(profile_stream);
        profile_stream = NULL;
    }
    profile_stream_owned = 0;
    kpep_profile_enabled = 0;
    kpep_profile_each_sample = 0;
    reset_interval = 0;
}

static uint32_t kpep_profile_parse_interval(const char *value)
{
    return kpep_log_parse_u32_env(value);
}

/* ************************************************************************************************
 * ************************************************************************************************
 * IMPLEMENTATION
 * ************************************************************************************************
 * ***********************************************************************************************/

void kpep_profile_init(void)
{
    const char *file_env;
    const char *interval_env;
    char filename[PATH_MAX] = {0};
    FILE *opened_profile = NULL;
    int opened_profile_owned = 0;
    uint32_t interval = 0;

    // Handle the mutex (create if needed, lock always)
    if (profile_mutex == NULL)
        profile_mutex = ossl_crypto_mutex_new();
    ossl_crypto_mutex_lock(profile_mutex);

    // Reset all values to their initial state before initializing the profile
    kpep_profile_close_stream();

    // Get the filename for profiling output from the environment variable KPEP_PROFILE_FILE
    file_env = getenv("KPEP_PROFILE_FILE");
    if (!file_env || file_env[0] == '\0') {
        // Not required; profiling is disabled if no file is specified
        goto end;;
    }

    // System stream or regular file?
    if (strcmp(file_env, "stdout") == 0) {
        opened_profile = stdout;
        opened_profile_owned = 0;
    } else if (strcmp(file_env, "stderr") == 0) {
        opened_profile = stderr;
        opened_profile_owned = 0;
    } else {
        if (strlen(file_env) >= sizeof(filename)) {
            kpep_profile_report_error_once("KPEP_PROFILE_FILE is too long; profiling disabled");
            goto end;
        }

        strncpy(filename, file_env, sizeof(filename) - 1);
        filename[sizeof(filename) - 1] = '\0';

        // Make sure the file is writable before proceeding
        if (!kpep_profile_touch_file(filename, &opened_profile)) {
            kpep_profile_report_error_once("KPEP_PROFILE_FILE '%s' is invalid or not writable; profiling disabled", filename);
            if (opened_profile) {
                fclose(opened_profile);
                opened_profile = NULL;
            }
            goto end;
        }

        opened_profile_owned = 1;
    }

    // Get the profiling interval from the environment variable KPEP_PROFILE_INTERVAL
    interval_env = getenv("KPEP_PROFILE_INTERVAL");
    if (interval_env && interval_env[0] != '\0') {
        interval = kpep_profile_parse_interval(interval_env);
        if (interval == 0 && strcmp(interval_env, "0") != 0) {
            kpep_profile_report_error_once("KPEP_PROFILE_INTERVAL '%s' is invalid; profiling disabled", interval_env);
            if (opened_profile_owned && opened_profile)
                fclose(opened_profile);
            opened_profile = NULL;
            goto end;
        }
    }

    // Check if profiling each sample is enabled via the environment variable KPEP_PROFILE_EACH_SAMPLE
    kpep_profile_each_sample = kpep_log_is_enabled_flag("KPEP_PROFILE_EACH_SAMPLE");

    // Set the profiling state
    profile_stream = opened_profile;
    profile_stream_owned = opened_profile_owned;
    reset_interval = interval;
    kpep_profile_enabled = 1;

end:
    // Always unlock
    ossl_crypto_mutex_unlock(profile_mutex);
}

void kpep_profile_fini(void)
{
    if (profile_mutex) {
        ossl_crypto_mutex_free(&profile_mutex);
        profile_mutex = NULL;
    }
    kpep_profile_close_stream();
}

uint32_t seed_stub_profile_now_us(void)
{
#if defined(_WIN32) || defined(_WIN64)
    LARGE_INTEGER freq;
    LARGE_INTEGER count;
    if (QueryPerformanceFrequency(&freq) && QueryPerformanceCounter(&count)) {
        return (uint32_t)((count.QuadPart * 1000000ULL) / freq.QuadPart);
    }
    return 0;
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (uint32_t)((uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL);
    struct timeval tv;
    if (gettimeofday(&tv, NULL) == 0)
        return (uint32_t)((uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec);
    return 0;
#endif
}

void seed_stub_profile_update(SEED_STUB_INFO *info, uint32_t last_us)
{
    if (!info)
        return;

    info->prof_count += 1;
    info->prof_last = last_us;
    info->prof_total += last_us;

    if (info->prof_count == 1) {
        info->prof_min = last_us;
        info->prof_max = last_us;
        info->prof_avg_g = last_us;
        info->prof_avg_w = last_us;
        return;
    }

    if (last_us < info->prof_min)
        info->prof_min = last_us;
    if (last_us > info->prof_max)
        info->prof_max = last_us;

    info->prof_avg_g = info->prof_total / info->prof_count;
    info->prof_avg_w = ((info->prof_avg_w * 3U) + last_us) / 4U;
}
