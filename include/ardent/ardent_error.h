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
 * ARDent Error Codes and related functions
 * ***********************************************************************************************/

#ifndef ARDENT_ERROR_H
#define ARDENT_ERROR_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* ************************************************************************************************
 * ************************************************************************************************
 * ERROR CODES
 * ************************************************************************************************
 * ***********************************************************************************************/

typedef uint32_t ARDENT_RESULT;      // A global return type

extern int ERR_LIB_ARDENT;           // Handle for accessing OpenSSL error functions

#define ARDENT_R_SUCCESS                     0
#define ARDENT_R_START                     101   /* MUST BE SAME AS FIRST INDEX */

/* MUST BE SEQUENTIAL !!! */
#define ARDENT_R_MALLOC_FAIL               101
#define ARDENT_R_NULL_ARG                  102
#define ARDENT_R_INVALID_ARG               103
#define ARDENT_R_ERROR_RETRIEVING_ENTROPY  104
#define ARDENT_R_FIPS_OPTEST               105

#define ARDENT_R_EXTERN_LOAD_FAILURE       106  /* Problem in DLSYM loading */
#define ARDENT_R_INTERNAL_HASH_FAIL        107
#define ARDENT_R_INTEGRITY_FAIL            108
#define ARDENT_R_NO_SLOTS                  109
#define ARDENT_R_LOG_BUGFIX_FAIL           110

#define ARDENT_R_SEED_INIT_FAIL            111
#define ARDENT_R_SEED_CPUID_FAIL           112
#define ARDENT_R_SEED_NOT_INSTANTIATED     113
#define ARDENT_R_SEED_IN_ERROR_STATE       114
#define ARDENT_R_SEED_NO_CPU_SUPPORT       115

#define ARDENT_R_SEED_BUFFER_TOO_SMALL     116
#define ARDENT_R_SEED_REQUEST_TOO_LARGE    117
#define ARDENT_R_SEED_INSUFFICIENT_ENTROPY 118
#define ARDENT_R_RESERVED_119              119
#define ARDENT_R_DRBG_RBG2_OVERFLOW        120

#define ARDENT_R_DRBG_INVALID_STATE        121
#define ARDENT_R_DRBG_INSUFFICIENT_ENTROPY 122
#define ARDENT_R_DRBG_REQUEST_TOO_LARGE    123
#define ARDENT_R_DRBG_NO_SEED_SOURCE       124
#define ARDENT_R_DRBG_FAILED_STARTUP       125

#define ARDENT_R_FILE_NOT_VALID            126
#define ARDENT_R_FILE_OPEN_ERROR           127
#define ARDENT_R_FILE_BAD_PERMISSIONS      128
#define ARDENT_R_FILE_NOT_FOUND            129
#define ARDENT_R_FILE_UNEXPECTED           130  // order s/b EOF->ERROR->UNEXPECTED

#define ARDENT_R_FILE_EOF                  131
#define ARDENT_R_FILE_ERROR                132
#define ARDENT_R_CONFIG_LOOKUP_FAILURE     133
#define ARDENT_R_CONFIG_PARAMETER_MISSING  134
#define ARDENT_R_CONFIG_PARAMETER_INVALID  135

#define ARDENT_R_RING_INVALID_SIZE         136
#define ARDENT_R_RING_NOT_POWER_OF_TWO     137
#define ARDENT_R_RING_FULL                 138
#define ARDENT_R_RING_EMPTY                139
#define ARDENT_R_RESERVED_140              140

#define ARDENT_R_THREAD_NOT_READY          141
#define ARDENT_R_THREAD_FAIL_START         142
#define ARDENT_R_MUTEX_FAIL_START          143
#define ARDENT_R_SEED_CONTROL_FATAL        144
#define ARDENT_R_RESERVED_145              145

#define ARDENT_R_SEED_NOT_READY            146
#define ARDENT_R_SEED_SOURCE_ERROR_1       147
#define ARDENT_R_SEED_SOURCE_ERROR_2       148
#define ARDENT_R_SEED_SOURCE_ERROR_3       149
#define ARDENT_R_SEED_FATAL_ERROR          150

#define ARDENT_R_END                       150   /* MUST BE SAME AS LAST INDEX */

#define ARDENT_R_COUNT (ARDENT_R_END-ARDENT_R_START+1)

// Function to retrieve reason string for a given error
const char* ardent_get_reason_string(ARDENT_RESULT result);

#ifdef __cplusplus
}
#endif
#endif /* ARDENT_ERROR_H */
