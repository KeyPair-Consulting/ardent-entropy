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
/*
 * DEVLOPER'S NOTE:
 * There is a bizarre bug wherein the call to the init_fn of the fi=rst sink causes a SEGFAULT.
 * This is a "dummy" (do-nothing) sink to address the issue.
 * See DEVELOPER'S NOTE in "kpep_logging/c" for more information.
 */

#include <stdio.h>

#include "kpep/kpep.h"
#include "kpep/kpep_names.h"

/* ************************************************************************************************
 * ************************************************************************************************
 * CONFIGURATION
 * ************************************************************************************************
 * ***********************************************************************************************/
 
/* ************************************************************************************************
 * ************************************************************************************************
 * SINK Functions
 * ************************************************************************************************
 * ***********************************************************************************************/
 
static KPEP_RESULT init_log_dummy(void* prov_ctx)
{
	#if defined (KPEP_TRACE_SINK)
    printf("*** -SINK: %s\n", __func__);
    #endif
	return KPEP_R_SUCCESS;
}

static void fini_log_dummy(void)
{
	#if defined (KPEP_TRACE_SINK)
    printf("*** -SINK: %s\n", __func__);
    #endif
	return; // Nothing to do
}

static const char* get_name_dummy(void)
{
	return "DUMMY";
}

static LogLevel get_level_dummy(void)
{
	return LOG_LVL_FATAL;
}

static void write_log_dummy(LogLevel level, const char* module, const char* fmt, va_list args)
{
	#if defined (KPEP_TRACE_SINK)
    printf("*** -SINK: %s\n", __func__);
    #endif
	return;
}

static void write_log_data_dummy(LogLevel level, const char* module, const char* label, unsigned char *bytes, size_t bytes_len)
{
	#if defined (KPEP_TRACE_SINK)
    printf("*** -SINK: %s\n", __func__);
    #endif
    return;
}

EXPORT_VISIBILITY_HIDDEN
SINK_FUNCTIONS sink_dummy = {
	.init_fn = &init_log_dummy,
	.fini_fn = &fini_log_dummy,
	.name_fn = &get_name_dummy,
	.level_fn = &get_level_dummy,
	.write_fn = &write_log_dummy,
	.write_data_fn = &write_log_data_dummy
};

