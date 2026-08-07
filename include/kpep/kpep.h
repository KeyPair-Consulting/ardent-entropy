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
 * KeyPair Management Provider Error Codes and related functions
 * ***********************************************************************************************/

#ifndef KPEP_H
#define KPEP_H
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

//  error codes
#include "kpep/kpep_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ************************************************************************************************
 * IDENTIFICATION
 * ***********************************************************************************************/

// Parameter name for retrieving a description of the seed sources
#define KPEP_PROV_PARAM_SEED_SOURCES "seed-sources"

// Parameter name for retrieving the entropy counting method (standard or restricted)
#define KPEP_PROV_PARAM_RESTRICTED_MODE "restricted-entropy-counting"

// Maximum length of the string containing the seed descriptions
#define SEED_CONTROL_DESCRIPTION_MAX 1024

// OpenSSL Properties for this module
#define KPEP_MODULE_PROPERTIES "provider=kpep,fips=yes"

// Internal DRBG strength (and thus, base seed request size)
#define KPEP_SECURITY_STRENGTH_BITS  256
#define KPEP_SECURITY_STRENGTH_BYTES  32

// Global context structure (opaque)
typedef struct kpep_provider_ctx_st KPEP_PROVIDER_CTX;

/* ************************************************************************************************
 * GENERAL UTILITY
 * ***********************************************************************************************/

// Useful macros
#define NELEM(x)    (sizeof(x)/sizeof((x)[0]))
#define MIN(x,y)    (((x)<(y))?(x):(y))
#define MAX(x,y)    (((x)>(y))?(x):(y))

// Safe memory handling
void  kpep_free(void* ptr);                  // Release memory
void  kpep_zeroize(void* ptr, size_t size);  // Set memory to zero
void  kpep_cleanse(void* ptr, size_t size);  // Set to zero then release
void* kpep_zalloc(size_t size);              // Allocate and set to zero

// Stores the trimmed input string into the given output buffer, which must be
// large enough to store the result.  If it is too small, the output is truncated.
size_t kpep_trimwhitespace(char *out, size_t len, const char *str);

// Manage visibility of functions
#define EXPORT_VISIBILITY_HIDDEN  __attribute__((visibility ("hidden")))
#define EXPORT_VISIBILITY_DEFAULT __attribute__((visibility("default")))

// Maximum key size supported for HMAC
#define KPEP_HMAC_MAX_KEY_SIZE 64

// Hash size (32B == 256b) for global usage (could be SHA2 or SHA3)
#define KPEP_GLOBAL_DIGEST_SIZE 32

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

typedef KPEP_RESULT (*init_log_fn)       (void* prov_ctx);
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
KPEP_RESULT kpep_log_add_sink(const SINK_FUNCTIONS *funcs);

// Get a "pretty" string description of each loaded sink, one-per-line; 
// Write to the provided (pre-zeroized) buffer of length 1024
#define KPEP_MAX_SINK_DESC_LEN 1024
void kpep_get_sinks_descs(char *buffer);

// Write a log entry to all active sinks
void kpep_log(LogLevel level, const char* module, const char *fmt, ...);

void kpep_log_data(LogLevel level, const char* module, const char* label, 
                    unsigned char *bytes, size_t bytes_len);

#define LOG_KPEP_ERROR(module, errnum) \
    kpep_log(LOG_LVL_ERR, (module), "[%s:%d] %s", __FILE__, __LINE__, kpep_get_reason_string((errnum)));

#define LOG_SIMPLE_ERROR(module, msg) \
    kpep_log(LOG_LVL_ERR, (module), "[%s:%d] %s", __FILE__, __LINE__, (msg));

#define LOG_FORMATTED_ERROR(module, fmt, ...) \
    kpep_log(LOG_LVL_ERR, (module), "[%s:%d] "fmt, __FILE__, __LINE__, __VA_ARGS__);

/* ************************************************************************************************
 * CONFIGURATION (optional, uses OpenSSL)
 * ***********************************************************************************************/

/* 
Wrapper function to access the OpenSSL core function (defined in kpep_prov.c) to retrieve parameters 
stored in the configuration file 'kpepmodule.cnf'.  If you aren't loading your configuration
via OpenSSL, this function can be ignored.  If you use this function, you will need to link the 
'kpep.so' shared object to get access to this function.

- prov_ctx is the provider context, which is used to access the core
- params is a pointer to an array of OSSL_PARAMS objects.  By making it a "void*", we remove
the dependency on header "openssl/params.h" and thus all ties to OpenSSL for external seeding

Typical usage would look like:

static KPEP_RESULT load_params(void* prov_ctx, MY_SOURCE_CTX *ctx)
{
    const char *local_str1 = NULL;
    const char *local_str2 = NULL;
    OSSL_PARAM params[3], *p = params;
    if (!prov_ctx)
        return KPEP_R_SUCCESS;
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "my-key-added-to-kpepmodule-file",
        (char **) &local_str1,
        sizeof(local_str1));
    *p++ = OSSL_PARAM_construct_utf8_ptr(
        "my-other-key-added-to-kpepmodule-file",
        (char **) &local_str2,
        sizeof(local_str2));
    *p = OSSL_PARAM_construct_end();

    if (!kpep_get_core_params(prov_ctx, params)) {
        return KPEP_R_CONFIG_LOOKUP_FAILURE;
    }

    // Convert the str value to an int
    ctx->int_value = atoi(local_str1);

    // Save (or copy?) the string value
    ctx->str_value = local_str2;  // Do NOT free this pointer!

    return KPEP_R_SUCCESS;
}
*/
int kpep_get_core_params(void* prov_ctx, void *params);
int kpep_get_core_param_bool(void *ctx, const char *name, int defval);

#ifdef __cplusplus
}
#endif
#endif /* KPEP_H */
