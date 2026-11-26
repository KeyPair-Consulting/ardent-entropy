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

#ifndef ARDENT_DEBUG_H
#define ARDENT_DEBUG_H
#pragma once

/* ************************************************************************************************
 * IPC limits and configuration
 * ***********************************************************************************************/

#define ARDENT_DEBUG_CONFIG_MAX 1024
#define ARDENT_DEBUG_ACK_FAILURE 0
#define ARDENT_DEBUG_ACK_SUCCESS 1

/* ************************************************************************************************
 * Centralized environment variable names for the debug subsystem.
 *
 * Current features:
 *   - Trace
 *   - Profile
 *
 * Naming convention for future extensibility (finite feature set):
 *   ARDENT_<FEATURE>_<SETTING>
 * ***********************************************************************************************/

/* ************************************************************************************************
 * TRACE feature env-vars
 * ***********************************************************************************************/

/* Enable trace feature with target: "stdout", "stderr", or filename path. */
#define ARDENT_ENV_TRACE_FILE           "ARDENT_TRACE_FILE"

/* Enable seed-source trace messages (enabled if "1"). */
#define ARDENT_ENV_TRACE_SEED           "ARDENT_TRACE_SEED"

/* Enable sink trace messages (enabled if "1"). */
#define ARDENT_ENV_TRACE_SINK           "ARDENT_TRACE_SINK"

/* Enable thread trace messages (enabled if "1"). */
#define ARDENT_ENV_TRACE_THREAD         "ARDENT_TRACE_THREAD"

/* Lazy trace write mode (buffers writes without immediate flush if "1"). */
#define ARDENT_ENV_TRACE_LAZY_WRITE     "ARDENT_TRACE_LAZY_WRITE"

/* ************************************************************************************************
 * PROFILE feature env-vars
 * ***********************************************************************************************/

/* Enable profiling feature with target: "stdout", "stderr", or filename path. */
#define ARDENT_ENV_PROFILE_FILE         "ARDENT_PROFILE_FILE"

/* Interval between write/reset operations (uint32). */
#define ARDENT_ENV_PROFILE_INTERVAL     "ARDENT_PROFILE_INTERVAL"

/* Enable per-sample profile behavior (enabled if "1"). */
#define ARDENT_ENV_PROFILE_EACH_SAMPLE  "ARDENT_PROFILE_EACH_SAMPLE"

/* ************************************************************************************************
 * FUTURE feature env-vars
 * ***********************************************************************************************/

/* Add future feature env-vars below as grouped blocks, for example:
 *
 * #define ARDENT_ENV_DIAG_ENABLE       "ARDENT_DIAG_ENABLE"
 * #define ARDENT_ENV_METRICS_FILE      "ARDENT_METRICS_FILE"
 * #define ARDENT_ENV_WATCHDOG_INTERVAL "ARDENT_WATCHDOG_INTERVAL"
 */

 /* ************************************************************************************************
 * TEMPLATE configuration file
 * Add future feature sections as needed.
 * ***********************************************************************************************/

static const char template_text[] =
    "# Debug template for ARDENT debugging (tracing and profiling).  This \n"
    "# template provides all the configuration fields with default settings.\n"
    "# Rename and modify as needed.\n"
    "# NOTE: Sections ([trace], [profile]) are optional. Omitted sections default to\n"
    "# off; included sections require all of their fields to be present.\n"
    "\n"
    "[trace]\n"
    "file = stdout\n"
    "seed = 0\n"
    "sink = 0\n"
    "thread = 0\n"
    "lazy-write = 0\n"
    "\n"
    "[profile]\n"
    "file = stdout\n"
    "interval = 0\n"
    "each-sample = 0\n"
    "format-csv = 0\n";

#endif /* ARDENT_DEBUG_H */