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

#ifndef KPEP_LOGGING_UTILITY_H
#define KPEP_LOGGING_UTILITY_H
#pragma once

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

int kpep_log_validate_filename(const char *path);
int kpep_log_is_enabled_flag(const char *name);
uint32_t kpep_log_parse_u32_env(const char *value);
void kpep_log_report_error_once(const char *tag, const char *fmt, ...);
uint64_t kpep_log_monotonic_us(void);
int kpep_log_touch_file(const char *path, FILE **out_stream, const char *banner);

#ifdef __cplusplus
}
#endif

#endif /* KPEP_LOGGING_UTILITY_H */
