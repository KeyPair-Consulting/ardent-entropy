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

 #ifndef KPEP_APP_COMMON_H
 #define KPEP_APP_COMMON_H
 
 #ifdef __cplusplus
 extern "C" {
 #endif
 
 #include <stdlib.h>
 #include <stdio.h>
 #include <string.h>

#define MAX_STRLEN 256

static void print_hex(const char* key, unsigned int col_width, const unsigned char* buf, unsigned int buflen) {
	unsigned int idx;

	if (key)
		printf("%-*s : ", col_width, key);
	else if (col_width)
		printf("%-*s", col_width, "");
	for (idx=0; idx<buflen; ++idx) {
		printf("%02X", buf[idx]);
		if (!idx) continue;                    // No formatting for first index
		if      ((idx+1)%32==0) printf("\n");  // Newline at 32 hex bytes
		else if ((idx+1)%8==0)  printf("  ");  // Spaces to break into 2x16 columns
	}
	printf("\n");
}

#ifdef __cplusplus
}
#endif
#endif /* KPEP_APP_COMMON_H */
