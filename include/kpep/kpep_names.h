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

/* ATTENTION:
 * This file contains the "public" names of the variables from your provider's
 * configuration file. It should be put in a public include location so your 
 * calling applications can reference these names.
 */

#ifndef KPEP_NAMES_H
#define KPEP_NAMES_H
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Type: OSSL_PARAM_UTF8_STRING
 * Purpose: Colon-separated byte array (HMAC-SHA3-256 of the kpep.so)
 */
#define KPEP_PROV_PARAM_MODULE_MAC    "module-mac"

/* **************************************************************************************** */
/* DEBUG CONTROL */
/* **************************************************************************************** */

/* Type: OSSL_PARAM_UTF8_STRING; local debug control endpoint path. */
#define KPEP_PROV_PARAM_DEBUG_IPC_PATH  "debug-ipc-path"

/* Type: OSSL_PARAM_UTF8_STRING; local control security mode: "none" or "peer". */
#define KPEP_PROV_PARAM_DEBUG_SECURITY  "debug-security"

/* **************************************************************************************** */
/* **************************************************************************************** */
/* SEED SOURCE CONTROL/MANAGEMENT */
/* **************************************************************************************** */
/* **************************************************************************************** */

/*
 * Type: OSSL_PARAM_UNSIGNED_INTEGER
 * Purpose: Security strength for the internal DRBG (either 128 or 256)
 */
#define KPEP_PROV_PARAM_SEED_STRENGTH  "seed.strength"

/*
 * Type: OSSL_PARAM_UTF8_STRING
 * Purpose: String to use for the "personalization string" for this device.  Should be
 *          unique per device.
 */
#define KPEP_PROV_PARAM_SEED_PERSO  "seed.perso"

/*
 * Type: OSSL_PARAM_UNSIGNED_INTEGER
 * Purpose: Whether to run the seed pipeline in async mode. Default: 0 (sync mode)
 */
#define KPEP_PROV_PARAM_SEED_ASYNC_MODE       "seed.async-mode"

/*
 * Type: OSSL_PARAM_UTF8_STRING
 * Purpose: RBG Construction Mode; whether to require entropy/reseed for each entropy request
 * If "RBG3", new entropy is required for each entropy request
 * If "RBG2", new entropy is used "on demand, if available", but requests can be serviced up 
 * to 2^17 total bits before reseed.  Any successful gather from validated source(s)  resets 
 * this counter.
 */
#define KPEP_PROV_PARAM_RBG_ENTROPY_MODE       "seed.rbg-entropy-mode"

/*
 * Type: OSSL_PARAM_UNSIGNED_INTEGER
 * Purpose: Require all seed sources to provide entgropy for each request. Default: 0
 * If "1", require all entropy sources to provide entropy for each request.
 * If "0", require at least one seed source to provide entropy for each request.
 */
#define KPEP_PROV_PARAM_REQ_ALL_SOURCES       "seed.req-all-sources"

/*
 * Type: OSSL_PARAM_UNSIGNED_INTEGER
 * Purpose: Whether to use the more restrictive entropy counting "Method 1".
 * This option is only in effect for "all" or "some" source settings (above).
 */
#define KPEP_PROV_PARAM_REQ_HARDWARE_SOURCE  "seed.req-hardware-source"

/* **************************************************************************************** */
/* **************************************************************************************** */
/* SEED SOURCE DETAIL */
/* **************************************************************************************** */
/* **************************************************************************************** */

/* 
 * Each seed source is activated and configured with a set of standard configuration keys, 
 * and can optionally define source-specific keys.  This creates a lot of redundant strings
 * to store and maintain.  This is achieved by concatenated, for example :
 * const char *name = KPEP_PROV_PARAM_SEED_JITTER"."KPEP_PROV_PARAM_SEED_ACTIVATE
 */

/* Seed source names; derived from section header names */
#define KPEP_PROV_PARAM_SEED_JITTER "seed.jitter"
#define KPEP_PROV_PARAM_SEED_RDSEED "seed.rdseed"
#define KPEP_PROV_PARAM_SEED_RDRAND "seed.rdrand"
#define KPEP_PROV_PARAM_SEED_OSRAND "seed.osrand"
#define KPEP_PROV_PARAM_SEED_EXTERN "seed.extseed"

/* *** Standard Configuration Keys ******************************************************** */

/*
 * Type: OSSL_PARAM_UNSIGNED_INTEGER
 * Purpose: Whether the seed source is active/utilized (boolean)
 */
#define KPEP_PROV_PARAM_SEED_ACTIVATE  "activate"
/*
 * Type: OSSL_PARAM_UNSIGNED_INTEGER
 * Purpose: Whether the seed source provides validated/qualified entropy (boolean)
 */
#define KPEP_PROV_PARAM_SEED_VALIDATED "validated"
/*
 * Type: OSSL_PARAM_UNSIGNED_INTEGER
 * Purpose:  Whether the seed source is a hardware source (for restrictive entropy counting method "1")
 */
#define KPEP_PROV_PARAM_SEED_HARDWARE "hardware-source"
/*
 * Type: OSSL_PARAM_UNSIGNED_INTEGER
 * Purpose: The size of the output block for this source
 */
#define KPEP_PROV_PARAM_SEED_BLOCK_SIZE  "block-size"
/*
 * Type: OSSL_PARAM_UNSIGNED_INTEGER
 * Purpose: The number of blocks of 'block-size' to meet 128-bit security strength
 */
#define KPEP_PROV_PARAM_SEED_BLOCK_COUNT "block-count"
/*
 * Type: OSSL_PARAM_UNSIGNED_INTEGER
 * Purpose: The number of times to retry for RdSeed and RdRand (each set independently).  
 *          This option is ignored by other sources.
 */
#define KPEP_PROV_PARAM_SEED_RETRY_COUNT "retry-count"
/*
 * Type: OSSL_PARAM_UNSIGNED_INTEGER
 * Purpose: Size of the ring buffer (in bits) to store entropy for async operations.  This value
 *          specifies the "min-entropy" or "quality entropy" to store.  The actual size of the 
 *          buffer can be significantly larger, based on the quality of the seed source, and is
 *          calculated based on the block-size and block-count configuration options.  This
 *          value must be a power-of-2.
 *          This should be sized with burst conditions in mind, but it won't help long-term
 *          resource starvation.
 */
#define KPEP_PROV_PARAM_SEED_RING_SIZE  "ring-size"

/* *** Options  ************************************************************************** */

/*
 * Type: OSSL_PARAM_UTF8_STRING
 * Purpose: Absolute path to the target file (e.g. "/dev/random" or "/usr/lib/mylib.so")
 */
#define KPEP_PROV_PARAM_SEED_FILEPATH    "filepath"

/*
 * Type: OSSL_PARAM_UTF8_STRING
 * Purpose: name of the symbol used for the "const STUB_FUNCTIONS <name>" array of pointers
 */
#define KPEP_PROV_PARAM_SEED_FUNCTIONS   "functions"

/*
 * Type: OSSL_PARAM_UNSIGNED_INTEGER
 * Purpose: Oversample rate (OSR) for jitter entropy seed source.
 */
#define KPEP_PROV_PARAM_SEED_JITTER_OVERSAMPLE    KPEP_PROV_PARAM_SEED_JITTER".oversample-rate"


/* **************************************************************************************** */
/* **************************************************************************************** */
/* LOGGING */
/* **************************************************************************************** */
/* **************************************************************************************** */

/*
 * Type: OSSL_PARAM_UNSIGNED_INTEGER
 * Purpose: Enable/Disable logging of FIPS indicators (boolean)
 */
#define KPEP_PROV_PARAM_LOG_FIPS_INDICATORS "logging.fips-indicators"

/*
 * Type: OSSL_PARAM_UNSIGNED_INTEGER
 * Purpose: Whether logs should be output to syslog
 */
#define KPEP_PROV_PARAM_LOG_SYSLOG_ACTIVATE    "logging.syslog.activate"

/*
 * Type: OSSL_PARAM_UTF8_STRING
 * Purpose: The standard logging level for syslog
 */
#define KPEP_PROV_PARAM_LOG_SYSLOG_LEVEL    "logging.syslog.level"

/*
 * Type: OSSL_PARAM_UNSIGNED_INTEGER
 * Purpose: Whether logs should be output to stderr
 */
#define KPEP_PROV_PARAM_LOG_STDERR_ACTIVATE    "logging.stderr.activate"

/*
 * Type: OSSL_PARAM_UTF8_STRING
 * Purpose: The standard logging level for syslog
 */
#define KPEP_PROV_PARAM_LOG_STDERR_LEVEL    "logging.stderr.level"

/*
 * Type: OSSL_PARAM_UNSIGNED_INTEGER
 * Purpose: Whether logs should be output to an external sink
 */
#define KPEP_PROV_PARAM_LOG_EXTERN_ACTIVATE    "logging.extlog.activate"

/*
 * Type: OSSL_PARAM_UTF8_STRING
 * Purpose: The standard logging level for syslog
 */
#define KPEP_PROV_PARAM_LOG_EXTERN_LEVEL    "logging.extlog.level"

/*
 * Type: OSSL_PARAM_UTF8_STRING
 * Purpose: Absolute path to the shared object (.so/.dll) to load
 */
#define KPEP_PROV_PARAM_LOG_EXTERN_FILEPATH    "logging.extlog.filepath"

/*
 * Type: OSSL_PARAM_UTF8_STRING
 * Purpose: name of the symbol used for the "const LOG_SINK <name>" array of pointers
 */
#define KPEP_PROV_PARAM_LOG_EXTERN_FUNCTIONS    "logging.extlog.functions"


/* **************************************************************************************** */
/* **************************************************************************************** */
/* ENVIRONMENT VARIABLES (non-OpenSSL startup) */
/* **************************************************************************************** */
/* **************************************************************************************** */

/*
 * Logging Sinks -- Set reporting level to enable
 */

#define ENV_LOG_SYSLOG_LEVEL         "KPEP_LOG_SYSLOG_LEVEL"

#define ENV_LOG_STDERR_LEVEL         "KPEP_LOG_STDERR_LEVEL"

#define ENV_LOG_EXTERN_LEVEL         "KPEP_LOG_EXTERN_LEVEL"
#define ENV_LOG_EXTERN_FILEPATH      "KPEP_LOG_EXTERN_FILEPATH"
#define ENV_LOG_EXTERN_FUNCTIONS     "KPEP_LOG_EXTERN_FUNCTIONS"

/* 
 * Seed source configuration
 */
#define ENV_SEED_JITTER_OSR          "KPEP_SEED_JITTER_OSR"   /* Over Sample Rate (default: 4) */

#define ENV_SEED_RDSEED_BLOCK_SIZE   "KPEP_SEED_RDSEED_BLOCK_SIZE"
#define ENV_SEED_RDSEED_BLOCK_COUNT  "KPEP_SEED_RDSEED_BLOCK_COUNT"
#define ENV_SEED_RDSEED_RETRY_COUNT  "KPEP_SEED_RDSEED_RETRY_COUNT"

#define ENV_SEED_RDRAND_BLOCK_SIZE   "KPEP_SEED_RDRAND_BLOCK_SIZE"
#define ENV_SEED_RDRAND_BLOCK_COUNT  "KPEP_SEED_RDRAND_BLOCK_COUNT"
#define ENV_SEED_RDRAND_RETRY_COUNT  "KPEP_SEED_RDRAND_RETRY_COUNT"

#define ENV_SEED_OSRAND_BLOCK_SIZE   "KPEP_SEED_OSRAND_BLOCK_SIZE"
#define ENV_SEED_OSRAND_BLOCK_COUNT  "KPEP_SEED_OSRAND_BLOCK_COUNT"
#define ENV_SEED_OSRAND_FILEPATH     "KPEP_SEED_OSRAND_FILEPATH"

#define ENV_SEED_EXTERN_BLOCK_SIZE   "KPEP_SEED_EXTERN_BLOCK_SIZE"
#define ENV_SEED_EXTERN_BLOCK_COUNT  "KPEP_SEED_EXTERN_BLOCK_COUNT"
#define ENV_SEED_EXTERN_FILEPATH     "KPEP_SEED_EXTERN_FILEPATH"

// Add additional environment variable names for triggering OpTest demonstrations
#ifdef FIPS_OPTEST
#include "kpep/kpep_names_optest.h"
#endif

#ifdef __cplusplus
}
#endif
#endif /* KPEP_NAMES_H */
