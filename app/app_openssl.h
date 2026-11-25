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

#ifndef ARDENT_APP_OPENSSL_H
#define ARDENT_APP_OPENSSL_H
 
#ifdef __cplusplus
extern "C" {
#endif
 
#include <stdio.h>
 
#include "openssl/params.h"
#include "openssl/err.h"

static void print_openssl_error(void) 
{
	unsigned long err = 0;
	while (1) {
		err = ERR_get_error();
		if (err < 1) {
			break;
		}
		fprintf(stderr, "OpenSSL error: %s\n", ERR_reason_error_string(err));
	}
}

#ifdef __cplusplus
}
#endif
#endif /* _APP_OPENSSL_H */
