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

#ifndef KPEP_ERROR_H
#define KPEP_ERROR_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* ************************************************************************************************
 * ************************************************************************************************
 * ERROR CODES
 * ************************************************************************************************
 * ***********************************************************************************************/

typedef uint32_t KPEP_RESULT;      // A global return type

extern int ERR_LIB_KPEP;           // Handle for accessing OpenSSL error functions

#define KPEP_R_SUCCESS                     0
#define KPEP_R_START                     101   /* MUST BE SAME AS FIRST INDEX */

/* MUST BE SEQUENTIAL !!! */
#define KPEP_R_MALLOC_FAIL               101
#define KPEP_R_NULL_ARG                  102
#define KPEP_R_INVALID_ARG               103
#define KPEP_R_ERROR_RETRIEVING_ENTROPY  104
#define KPEP_R_FIPS_OPTEST               105

#define KPEP_R_EXTERN_LOAD_FAILURE       106
#define KPEP_R_INTERNAL_HASH_FAIL        107
#define KPEP_R_KDF_FAILED_OPERATION      108
#define KPEP_R_LOG_NO_SINK_SLOTS         109
#define KPEP_R_LOG_BUGFIX_FAIL           110

#define KPEP_R_SEED_FATAL_ERROR          111
#define KPEP_R_SEED_NOT_READY            112
#define KPEP_R_SEED_NOT_INSTANTIATED     113
#define KPEP_R_SEED_IN_ERROR_STATE       114
#define KPEP_R_SEED_NO_CPU_SUPPORT       115

#define KPEP_R_SEED_BUFFER_TOO_SMALL     116
#define KPEP_R_SEED_NO_SLOTS             117
#define KPEP_R_SEED_FILE_EOF             118
#define KPEP_R_SEED_FILE_ERROR           119
#define KPEP_R_SEED_CANNOT_OPEN_FILE     120

#define KPEP_R_DRBG_INVALID_STATE        121
#define KPEP_R_DRBG_INSUFFICIENT_ENTROPY 122
#define KPEP_R_DRBG_REQUEST_TOO_LARGE    123
#define KPEP_R_DRBG_NO_SEED_SOURCE       124
#define KPEP_R_DRBG_FAILED_STARTUP       125

#define KPEP_R_FILE_NOT_VALID            126
#define KPEP_R_FILE_FAILED_TO_OPEN       127
#define KPEP_R_FILE_BAD_PERMISSIONS      128
#define KPEP_R_FILE_NOT_FOUND            129
#define KPEP_R_FILE_UNEXPECTED           130

#define KPEP_R_CONFIG_LOOKUP_FAILURE     131
#define KPEP_R_CONFIG_PARAMETER_MISSING  132
#define KPEP_R_CONFIG_PARAMETER_INVALID  133
#define KPEP_R_KDF_CAST_FAILED           134
#define KPEP_R_LOCK_ERROR                135

#define KPEP_R_RING_INVALID_SIZE         136
#define KPEP_R_RING_NOT_POWER_OF_TWO     137
#define KPEP_R_RING_FULL                 138
#define KPEP_R_RING_EMPTY                139
#define KPEP_R_RESERVED_140              140

#define KPEP_R_THREAD_FAIL_START         141
#define KPEP_R_RESERVED_142              142
#define KPEP_R_RESERVED_143              143
#define KPEP_R_RESERVED_144              144
#define KPEP_R_RESERVED_145              145

#define KPEP_R_END                       145   /* MUST BE SAME AS LAST INDEX */

#define KPEP_R_COUNT (KPEP_R_END-KPEP_R_START+1)

// Function to retrieve reason string for a given error
const char* kpep_get_reason_string(KPEP_RESULT result);

#ifdef __cplusplus
}
#endif
#endif /* KPEP_ERROR_H */
