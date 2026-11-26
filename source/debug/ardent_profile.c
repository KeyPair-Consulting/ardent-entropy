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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug_utility.h"
#include "debug_core.h"
#include "ardent/ardent_names.h"
#include "../seeding/seed_sources.h"

/* ************************************************************************************************
 * ************************************************************************************************
 * DEFINITIONS
 * ************************************************************************************************
 * ***********************************************************************************************/

// Globally available enable flag
int ardent_profile_enabled = 0;
int ardent_profile_each_sample = 0;
static int ardent_profile_format_csv = 0;

static ARDENT_DEBUG_SINK *profile_sink = NULL;

// Reset period used by the profile subsystem, in the same style as trace startup
static uint32_t reset_interval = 0;

static void ardent_profile_close_stream(void)
{
    ardent_debug_sink_release(&profile_sink);
    ardent_profile_enabled = 0;
    ardent_profile_each_sample = 0;
    ardent_profile_format_csv = 0;
    reset_interval = 0;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * IMPLEMENTATION
 * ************************************************************************************************
 * ***********************************************************************************************/

static const char profile_header[] =
        "Type        : Source                   | Size (B) | Last (us) | Mean (us) | Window (us) | Min (us) | Max (us) | Count\n";
static const char profile_csv_header[] =
    "Type,Source,Size (B),Last (us),Mean (us),Window (us),Min (us),Max (us),Count\n";

void ardent_profile_init(const ARDENT_DEBUG_PROFILE_CONFIG *config)
{
    // Reset all values to their initial state before initializing the profile
    ardent_profile_close_stream();
    if (!config)
        return;

    if (!config->file || config->file[0] == '\0') {
        return;
    }

    ardent_profile_each_sample = config->each_sample;
    ardent_profile_format_csv = config->format_csv;

    profile_sink = ardent_debug_sink_acquire(config->file, "PROFILE ERROR", "profile.file");
    if (!profile_sink) {
        ardent_profile_each_sample = 0;
        return;
    }

    // Write the header
    ardent_debug_sink_write(profile_sink,
        ardent_profile_format_csv ? profile_csv_header : profile_header, 1);

    // Set the profiling state
    reset_interval = config->interval;
    ardent_profile_enabled = 1;

}

void ardent_profile_fini(void)
{
    ardent_profile_close_stream();
}

uint32_t seed_stub_profile_now_us(void)
{
    return (uint32_t)ardent_debug_monotonic_us();
}

static void ardent_profile_write_line(const char *label, const SEED_STUB_INFO *info, uint32_t summary)
{
    char line[256];

    if (!profile_sink || !info)
        return;

    if (ardent_profile_format_csv) {
        snprintf(line, sizeof(line), "%s,%s,%u,%u,%u,%u,%u,%u,%u\n",
            label, info->name, (summary) ? (uint32_t)info->prof_total_sz : info->prof_last_sz,
            info->prof_last, info->prof_avg_g, info->prof_avg_w,
            info->prof_min, info->prof_max, info->prof_count);
    } else {
        snprintf(line, sizeof(line),
            "%-12s: %-24s | %8u | %9u | %9u | %11u | %8u | %8u | %5u\n",
            label, info->name, (summary) ? (uint32_t)info->prof_total_sz : info->prof_last_sz,
            info->prof_last, info->prof_avg_g, info->prof_avg_w,
            info->prof_min, info->prof_max, info->prof_count);
    }
    ardent_debug_sink_write(profile_sink, line, 1);
}

void seed_stub_profile_update(SEED_STUB_INFO *info, uint32_t last_us, uint32_t last_sz)
{
    if (!info)
        return;

    info->prof_count += 1;
    info->prof_last = last_us;
    info->prof_last_sz = last_sz;
    info->prof_total += last_us;
    info->prof_total_sz += last_sz;

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

    if (ardent_profile_enabled && profile_sink) {
        if (ardent_profile_each_sample) {
            ardent_profile_write_line("PROF-SAMPLE", info, 0);
        }

        if (reset_interval > 0) {
            uint64_t now_us = ardent_debug_monotonic_us();
            if (info->prof_last_reset_us == 0) {
                info->prof_last_reset_us = now_us;
            }
            else {
                if ((now_us - info->prof_last_reset_us) >= ((uint64_t)reset_interval * 1000000ULL)) {
                    ardent_profile_write_line("PROF-SUMMARY", info, 1);

                    info->prof_count = 0;
                    info->prof_total = 0;
                    info->prof_total_sz = 0;
                    info->prof_min = UINT32_MAX;
                    info->prof_max = 0;
                    info->prof_avg_g = 0;
                    info->prof_avg_w = 0;
                    info->prof_last_reset_us = now_us;
                }
            }
        }
    }
}
