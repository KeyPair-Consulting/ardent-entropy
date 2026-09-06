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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug_utility.h"
#include "debug_core.h"
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

static KPEP_DEBUG_SINK *profile_sink = NULL;

// Reset period used by the profile subsystem, in the same style as trace startup
static uint32_t reset_interval = 0;
static uint64_t last_reset_us = 0;

static void kpep_profile_close_stream(void)
{
    kpep_debug_sink_release(&profile_sink);
    kpep_profile_enabled = 0;
    kpep_profile_each_sample = 0;
    reset_interval = 0;
    last_reset_us = 0;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * IMPLEMENTATION
 * ************************************************************************************************
 * ***********************************************************************************************/

void kpep_profile_init(const KPEP_DEBUG_PROFILE_CONFIG *config)
{
    // Reset all values to their initial state before initializing the profile
    kpep_profile_close_stream();
    if (!config)
        return;

    if (!config->file || config->file[0] == '\0') {
        return;
    }

    kpep_profile_each_sample = config->each_sample;

    profile_sink = kpep_debug_sink_acquire(config->file, "PROFILE ERROR", "profile.file");
    if (!profile_sink) {
        kpep_profile_each_sample = 0;
        return;
    }

    // Set the profiling state
    reset_interval = config->interval;
    last_reset_us = kpep_debug_monotonic_us();
    kpep_profile_enabled = 1;
}

void kpep_profile_fini(void)
{
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

static void kpep_profile_write_line(const char *label, const SEED_STUB_INFO *info, uint32_t avg_us)
{
    char line[256];

    if (!profile_sink || !info)
        return;

    snprintf(line, sizeof(line),
        "%-12s: %-24s | last: %6u us | avg: %6u us | min: %6u us | max: %6u us | count: %u\n",
        label, info->name, info->prof_last, avg_us, info->prof_min, info->prof_max, info->prof_count);
    kpep_debug_sink_write(profile_sink, line, 1);
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
    } else {
        if (last_us < info->prof_min)
            info->prof_min = last_us;
        if (last_us > info->prof_max)
            info->prof_max = last_us;

        info->prof_avg_g = info->prof_total / info->prof_count;
        info->prof_avg_w = ((info->prof_avg_w * 3U) + last_us) / 4U;
    }

    if (kpep_profile_enabled && kpep_profile_each_sample && profile_sink) {
        kpep_profile_write_line("PROF-SAMPLE ", info, info->prof_avg_w);
    }

    if (kpep_profile_enabled && reset_interval > 0 && profile_sink) {
        uint64_t now_us = kpep_debug_monotonic_us();
        if ((now_us - last_reset_us) >= ((uint64_t)reset_interval * 1000000ULL)) {
            kpep_profile_write_line("PROF-SUMMARY", info, info->prof_avg_g);

            info->prof_count = 0;
            info->prof_total = 0;
            info->prof_min = 0;
            info->prof_max = 0;
            info->prof_avg_g = 0;
            info->prof_avg_w = 0;
            last_reset_us = now_us;
        }
    }
}
