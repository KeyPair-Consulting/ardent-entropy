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
 * Purpose: Whether to use the more restrictive entropy counting "Method 1"
 */
#define KPEP_PROV_PARAM_RESTRICTIVE_COUNTING  "seed.restricted-entropy-counting"

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

#define ENV_SEED_RDRAND_BLOCK_SIZE   "KPEP_SEED_RDRAND_BLOCK_SIZE"
#define ENV_SEED_RDRAND_BLOCK_COUNT  "KPEP_SEED_RDRAND_BLOCK_COUNT"

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
