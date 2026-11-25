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
 * ***********************************************************************************************
 * ARDent Management Provider Error Codes and related functions
 * ***********************************************************************************************/

#ifndef ARDENT_H
#define ARDENT_H
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

//  error codes
#include "ardent/ardent_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ************************************************************************************************
 * IDENTIFICATION
 * ***********************************************************************************************/

// Parameter name for retrieving a description of the seed sources
#define ARDENT_PROV_PARAM_SEED_SOURCES "seed-sources"

// Parameter name for retrieving the entropy counting method (standard or restricted)
#define ARDENT_PROV_PARAM_RESTRICTED_MODE "restricted-entropy-counting"

// Maximum length of the string containing the seed descriptions
#define SEED_CONTROL_DESCRIPTION_MAX 1024

// OpenSSL Properties for this module
#define ARDENT_MODULE_PROPERTIES "provider=ardent,fips=yes"

// Internal DRBG strength (and thus, base seed request size)
#define ARDENT_SECURITY_STRENGTH_BITS  256
#define ARDENT_SECURITY_STRENGTH_BYTES  32

// Global context structure (opaque)
typedef struct ardent_provider_ctx_st ARDENT_PROVIDER_CTX;

/* ************************************************************************************************
 * GENERAL UTILITY
 * ***********************************************************************************************/

// Useful macros
#define NELEM(x)    (sizeof(x)/sizeof((x)[0]))
#define MIN(x,y)    (((x)<(y))?(x):(y))
#define MAX(x,y)    (((x)>(y))?(x):(y))

// Safe memory handling
void  ardent_free(void* ptr);                  // Release memory
void  ardent_zeroize(void* ptr, size_t size);  // Set memory to zero
void  ardent_cleanse(void* ptr, size_t size);  // Set to zero then release
void* ardent_zalloc(size_t size);              // Allocate and set to zero

// Stores the trimmed input string into the given output buffer, which must be
// large enough to store the result.  If it is too small, the output is truncated.
size_t ardent_trimwhitespace(char *out, size_t len, const char *str);

// Use atoi to parse a string into a uint32_t value safely
int parse_uint32(const char *text, uint32_t *value);

// Manage visibility of functions
#define EXPORT_VISIBILITY_HIDDEN  __attribute__((visibility ("hidden")))
#define EXPORT_VISIBILITY_DEFAULT __attribute__((visibility("default")))

// Maximum key size supported for HMAC
#define ARDENT_HMAC_MAX_KEY_SIZE 64

// Hash size (32B == 256b) for global usage (could be SHA2 or SHA3)
#define ARDENT_GLOBAL_DIGEST_SIZE 32

// Fallback definition for PATH_MAX if not defined by the system headers
#ifndef PATH_MAX
# if defined(_WIN32) || defined(_WIN64)
#  define PATH_MAX 260
# else
#  define PATH_MAX 4096
# endif
#endif

/* ************************************************************************************************
 * LOGGER
 * ***********************************************************************************************/

typedef enum { 
    LOG_LVL_FATAL = 0,	/* 0 == (FATAL) system is unusable and cannot be used */
    LOG_LVL_ALERT,      /* 1 == (NOT USED) action must be taken immediately */
    LOG_LVL_CRIT,       /* 2 == (NOT USED) critical conditions */
    LOG_LVL_ERR,        /* 3 == (MOST COMMON) error conditions */
    LOG_LVL_WARN,       /* 4 == (UNCOMMON) warning conditions; typically notice about failed init or conditions */
    LOG_LVL_NOTICE,     /* 5 == (NOT USED) normal but significant condition */
    LOG_LVL_INFO,       /* 6 == (COMMON) informational and general operational status */
    LOG_LVL_DEBUG,      /* 7 == (COMPILE-TIME OPTION) debug-level messages */
} LogLevel;
#define LEVEL_IN_RANGE(lvl) (((lvl) >= LOG_LVL_FATAL) && ((lvl) <= LOG_LVL_DEBUG))

typedef ARDENT_RESULT (*init_log_fn)       (void* prov_ctx);
typedef void        (*fini_log_fn)       (void);
typedef const char* (*get_name_fn)       (void);
typedef LogLevel    (*get_level_fn)      (void);
typedef void        (*write_log_fn)      (LogLevel level, const char* module, const char* fmt, va_list args);
typedef void        (*write_log_data_fn) (LogLevel level, const char* module, const char* label, unsigned char *bytes, size_t bytes_len);

typedef struct sink_function_st {
    init_log_fn       init_fn;
    fini_log_fn       fini_fn;
    get_name_fn       name_fn;
    get_level_fn      level_fn;
    write_log_fn      write_fn;
    write_log_data_fn write_data_fn;
} SINK_FUNCTIONS;

LogLevel    read_log_level_string(const char *level);
const char*  get_log_level_string(LogLevel level);

// Add a new sink to the logging subsystem
ARDENT_RESULT ardent_log_add_sink(const SINK_FUNCTIONS *funcs);

// Get a "pretty" string description of each loaded sink, one-per-line; 
// Write to the provided (pre-zeroized) buffer of length 1024
#define ARDENT_MAX_SINK_DESC_LEN 1024
void ardent_get_sinks_descs(char *buffer);

// Write a log entry to all active sinks
void ardent_log(LogLevel level, const char* module, const char *fmt, ...);

void ardent_log_data(LogLevel level, const char* module, const char* label, 
                    unsigned char *bytes, size_t bytes_len);

#define LOG_ARDENT_ERROR(module, errnum) \
    ardent_log(LOG_LVL_ERR, (module), "[%s:%d] %s", __FILE__, __LINE__, ardent_get_reason_string((errnum)));

#define LOG_SIMPLE_ERROR(module, msg) \
    ardent_log(LOG_LVL_ERR, (module), "[%s:%d] %s", __FILE__, __LINE__, (msg));

#define LOG_FORMATTED_ERROR(module, fmt, ...) \
    ardent_log(LOG_LVL_ERR, (module), "[%s:%d] "fmt, __FILE__, __LINE__, __VA_ARGS__);

/* ************************************************************************************************
 * TRACING
 * ***********************************************************************************************/

#ifndef ARDENT_TRACE_DISABLED

// Runtime tracing enabled through environment vars read in ardent_trace_init().  These cache
// those values between calls for quick access.  Apps/Users must call "ardent_trace_init()"
// each time the runtime config is changed for these values to be refreshed.
extern int ardent_trace_seed_enabled;
extern int ardent_trace_sink_enabled;
extern int ardent_trace_thread_enabled;
extern int ardent_trace_strict_mode;

// Write a trace entry to the active trace target (stdout or trace file)
void ardent_trace(const char* module, const char* msg);
void ardent_trace_sub(const char* module, const char* submodule, const char* msg);
void ardent_trace_fmt(const char* module, const char* fmt, ...);
void ardent_trace_sub_fmt(const char* module, const char* submodule, const char* fmt, ...);

#define TRACE_START \
    ardent_trace_fmt((MODULE_NAME), "START %s", __func__)

#define TRACE_END \
    ardent_trace_fmt((MODULE_NAME), "END %s", __func__)

#define TRACE_START_SUB \
    ardent_trace_sub_fmt((MODULE_NAME), (ctx) ? (ctx)->desc : "NULL", "START %s", __func__)

#define TRACE_END_SUB \
    ardent_trace_sub_fmt((MODULE_NAME), (ctx) ? (ctx)->desc : "NULL", "END %s", __func__)

#endif

/* ************************************************************************************************
 * PROFILING
 * ***********************************************************************************************/

extern int ardent_profile_enabled;


/* ************************************************************************************************
 * CONFIGURATION (optional, uses OpenSSL)
 * ***********************************************************************************************/

/* 
Wrapper function to access the OpenSSL core function (defined in ardent_prov.c) to retrieve parameters 
stored in the configuration file 'ardentmodule.cnf'.  If you aren't loading your configuration
via OpenSSL, this function can be ignored.  If you use this function, you will need to link the 
'ardent.so' shared object to get access to this function.

- prov_ctx is the provider context, which is used to access the core
- params is a pointer to an array of OSSL_PARAMS objects.  By making it a "void*", we remove
the dependency on header "openssl/params.h" and thus all ties to OpenSSL for external seeding

Typical usage would look like:

static ARDENT_RESULT load_params(void* prov_ctx, MY_SOURCE_CTX *ctx)
{
    const char *local_str1 = NULL;
    const char *local_str2 = NULL;
    OSSL_PARAM params[3], *p = params;

    if (!prov_ctx)
        return ARDENT_R_SUCCESS;
        
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "my-key-added-to-ardentmodule-file",
        (char **) &local_str1,
        sizeof(local_str1));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "my-other-key-added-to-ardentmodule-file",
        (char **) &local_str2,
        sizeof(local_str2));
    *p = OSSL_PARAM_construct_end();

    if (!ardent_get_core_params(prov_ctx, params)) {
        return ARDENT_R_CONFIG_LOOKUP_FAILURE;
    }

    // Convert the str value to an int
    ctx->int_value = atoi(local_str1);

    // Save (or copy?) the string value
    ctx->str_value = local_str2;  // Do NOT free this pointer!

    return ARDENT_R_SUCCESS;
}
*/
int ardent_get_core_params(void* prov_ctx, void *params);
int ardent_get_core_param_bool(void *ctx, const char *name, int defval);

#ifdef __cplusplus
}
#endif
#endif /* ARDENT_H */
