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

#ifndef ARDENT_DEBUG_CORE_H
#define ARDENT_DEBUG_CORE_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ardent_debug_sink_st ARDENT_DEBUG_SINK;

typedef struct ardent_debug_trace_config_st {
    const char *file;
    int seed;
    int sink;
    int thread;
    int lazy_write;
} ARDENT_DEBUG_TRACE_CONFIG;

typedef struct ardent_debug_profile_config_st {
    const char *file;
    uint32_t interval;
    int each_sample;
    int format_csv;
} ARDENT_DEBUG_PROFILE_CONFIG;

/* Initialize the debug features in their disabled state. */
void ardent_debug_init(void);

/* Start immutable provider-configured debug control after provider startup. */
void ardent_debug_control_init(void *prov_ctx);

/* Stop debug control and finalize all debug features. */
void ardent_debug_fini(void);

ARDENT_DEBUG_SINK *ardent_debug_sink_acquire(const char *name,
                                         const char *error_tag,
                                         const char *env_name);
void ardent_debug_sink_release(ARDENT_DEBUG_SINK **sink);
int ardent_debug_sink_write(ARDENT_DEBUG_SINK *sink, const char *text, int flush_output);


/* ************************************************************************************************
 * Debug features interfaces
 * ***********************************************************************************************/

// Tracing of function calls within the ARDENT library
void ardent_trace_init(const ARDENT_DEBUG_TRACE_CONFIG *config);
void ardent_trace_fini(void);

// Performance tracking for seed sources
void ardent_profile_init(const ARDENT_DEBUG_PROFILE_CONFIG *config);
void ardent_profile_fini(void);

// Extensibility for other debug components
//void ardent_other_init(void);
//void ardent_other_fini(void);

#ifdef __cplusplus
}
#endif

#endif /* ARDENT_DEBUG_CORE_H */