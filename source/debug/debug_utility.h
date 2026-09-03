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

#ifndef KPEP_DEBUG_UTILITY_H
#define KPEP_DEBUG_UTILITY_H
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

int kpep_debug_validate_filename(const char *path);
/* Return 1 only when the named environment variable is exactly "1". */
int kpep_debug_is_enabled_flag(const char *name);
int kpep_debug_is_stream_name(const char *name, FILE **out_stream);
int kpep_debug_parse_bool(const char *value, int *out);
uint32_t kpep_debug_parse_u32_env(const char *value);
int kpep_debug_parse_interval(const char *value, uint32_t *out);
void kpep_debug_report_error_once(const char *tag, const char *fmt, ...);
uint64_t kpep_debug_monotonic_us(void);
int kpep_debug_open_output(const char *name,
						   const char *banner,
						   FILE **out_stream,
						   int *out_owned,
						   char *errbuf,
						   size_t errbuf_len);

#ifdef __cplusplus
}
#endif

#endif /* KPEP_DEBUG_UTILITY_H */
