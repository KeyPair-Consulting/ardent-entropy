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

#ifndef ARDENT_INTEGRITY_H
#define ARDENT_INTEGRITY_H
#pragma once

#include "ardent/ardent.h"  // For ARDENT_RESULT

#ifdef __cplusplus
extern "C" {
#endif

/* Default HMAC Key used for the integrity file check */
extern const unsigned char ardent_integrity_key[];
extern const size_t ardent_integrity_key_len;

/* Generate a MAC for the target of the given filename */
/* Pass in (NULL, 0) for the (key, key_len) to use the default key (above) */
ARDENT_RESULT integrity_check_file(const char* filename, 
                                 const unsigned char *key, size_t key_len,
                                 unsigned char *mac, size_t *mac_len);

#ifdef __cplusplus
}
#endif
#endif /* ARDENT_INTEGRITY_H */
