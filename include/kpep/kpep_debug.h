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

#ifndef KPEP_DEBUG_H
#define KPEP_DEBUG_H
#pragma once

/* ************************************************************************************************
 * IPC limits and configuration
 * ***********************************************************************************************/

#define KPEP_DEBUG_CONFIG_MAX 1024
#define KPEP_DEBUG_ACK_FAILURE 0
#define KPEP_DEBUG_ACK_SUCCESS 1

/* ************************************************************************************************
 * Centralized environment variable names for the debug subsystem.
 *
 * Current features:
 *   - Trace
 *   - Profile
 *
 * Naming convention for future extensibility (finite feature set):
 *   KPEP_<FEATURE>_<SETTING>
 * ***********************************************************************************************/

/* ************************************************************************************************
 * TRACE feature env-vars
 * ***********************************************************************************************/

/* Enable trace feature with target: "stdout", "stderr", or filename path. */
#define KPEP_ENV_TRACE_FILE           "KPEP_TRACE_FILE"

/* Enable seed-source trace messages (enabled if "1"). */
#define KPEP_ENV_TRACE_SEED           "KPEP_TRACE_SEED"

/* Enable sink trace messages (enabled if "1"). */
#define KPEP_ENV_TRACE_SINK           "KPEP_TRACE_SINK"

/* Enable thread trace messages (enabled if "1"). */
#define KPEP_ENV_TRACE_THREAD         "KPEP_TRACE_THREAD"

/* Lazy trace write mode (buffers writes without immediate flush if "1"). */
#define KPEP_ENV_TRACE_LAZY_WRITE     "KPEP_TRACE_LAZY_WRITE"

/* ************************************************************************************************
 * PROFILE feature env-vars
 * ***********************************************************************************************/

/* Enable profiling feature with target: "stdout", "stderr", or filename path. */
#define KPEP_ENV_PROFILE_FILE         "KPEP_PROFILE_FILE"

/* Interval between write/reset operations (uint32). */
#define KPEP_ENV_PROFILE_INTERVAL     "KPEP_PROFILE_INTERVAL"

/* Enable per-sample profile behavior (enabled if "1"). */
#define KPEP_ENV_PROFILE_EACH_SAMPLE  "KPEP_PROFILE_EACH_SAMPLE"

/* ************************************************************************************************
 * FUTURE feature env-vars
 * ***********************************************************************************************/

/* Add future feature env-vars below as grouped blocks, for example:
 *
 * #define KPEP_ENV_DIAG_ENABLE       "KPEP_DIAG_ENABLE"
 * #define KPEP_ENV_METRICS_FILE      "KPEP_METRICS_FILE"
 * #define KPEP_ENV_WATCHDOG_INTERVAL "KPEP_WATCHDOG_INTERVAL"
 */

 /* ************************************************************************************************
 * TEMPLATE configuration file
 * Add future feature sections as needed.
 * ***********************************************************************************************/

static const char template_text[] =
    "# KeyPair Entropy Provider runtime debugging configuraton file template \n"
    "# Debug template for KPEP debugging (tracing and profiling).  This \n"
    "# template provides all the configuration fields with default settings.\n"
    "# Rename and modify as needed.\n"
    "# NOTE: All fields in [trace] and [profile] must be present.\n"
    "\n"
    "[trace]\n"
    "file = stdout\n"
    "seed = 0\n"
    "sink = 0\n"
    "thread = 0\n"
    "strict = 0\n"
    "\n"
    "[profile]\n"
    "file = stdout\n"
    "interval = 0\n"
    "each-sample = 0\n";

#endif /* KPEP_DEBUG_H */