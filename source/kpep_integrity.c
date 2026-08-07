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

#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "kpep/kpep.h"
#include "kpep_internal.h"
#include "kpep_integrity.h"

/* ************************************************************************************************
 * ************************************************************************************************
 * GENERATE HMAC
 * ************************************************************************************************
 * ***********************************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "crypto/hmac.h"

// TODO: CHANGE ME!
EXPORT_VISIBILITY_HIDDEN
const unsigned char kpep_integrity_key[] = { 
    0x4B,0x65,0x79,0x50,0x61,0x69,0x72,0x20,   // "KeyPair "
    0x46,0x49,0x50,0x53,0x20,                  // "FIPS "
    0x4D,0x61,0x6E,0x61,0x67,0x65,0x72         // "Manager"
};
EXPORT_VISIBILITY_HIDDEN
const size_t kpep_integrity_key_len = sizeof(kpep_integrity_key);

#define FILE_BUFFER_SIZE 4096

/* Return: NULL if regular file, else brief error message */
static const char* is_valid_file(const char *filename)
{
	struct stat st;

	if (0 != lstat(filename, &st)) {
		return "lstat failed, probably no such file";
	}

	switch (st.st_mode & S_IFMT) {
	case S_IFLNK:
	case S_IFREG:
		return NULL;
	case S_IFSOCK:
		return "socket";
	case S_IFBLK:
		return "block device";
	case S_IFDIR:
		return "directory";
	case S_IFCHR:
		return "character device";
	case S_IFIFO:
		return "FIFO";
	}
	return NULL;
}

EXPORT_VISIBILITY_HIDDEN
KPEP_RESULT integrity_check_file(const char* filename, 
                            	 const unsigned char *key, size_t key_len,
                            	 unsigned char *mac, size_t *mac_len) 
{
    KPEP_RESULT rv = KPEP_R_SUCCESS; // Assume success

    FILE *fp = NULL;
    unsigned char *buffer = NULL;
    size_t bytes_read = 0;

    HMAC_CTX *hctx;
    const char *file_type = NULL;

    // Validate arguments
    if (!mac) {
        if (mac_len) {
            *mac_len = KPEP_GLOBAL_DIGEST_SIZE;
            return 0; // ok
        }
        else 
            return KPEP_R_NULL_ARG;  // !mac and !mac_len... what do you want?
    }

    if (!filename || !mac_len || *mac_len < KPEP_GLOBAL_DIGEST_SIZE) {
        return KPEP_R_INVALID_ARG;
    }
    if ((file_type = is_valid_file(filename)) != NULL) {
        return KPEP_R_FILE_NOT_VALID;
    }

    // Default Key
    if (!key || !key_len) {
        key = (unsigned char*) kpep_integrity_key;
        key_len = kpep_integrity_key_len;
    }

    // Open file
    fp = fopen(filename, "rb");
    if (!fp) {
        switch (errno) {
            case EACCES:
                rv = KPEP_R_FILE_BAD_PERMISSIONS;
                break;
            case ENOENT:
                rv = KPEP_R_FILE_NOT_FOUND;
                break;
            default:
                rv = KPEP_R_FILE_UNEXPECTED;
        }
        goto err;
    }

    // Initialize the HMAC
    hctx = hmac_ctx_new();
    if (!hctx) {
        rv = KPEP_R_MALLOC_FAIL;
        goto err;
    }

    // Initialize the read buffer
    buffer = kpep_zalloc(FILE_BUFFER_SIZE);
    if (!buffer) {
        rv = KPEP_R_MALLOC_FAIL;
        goto err;
    }

    // Reset error before file operations (no POSIX guarantee that errno is set on a file error)
    clearerr(fp);
    errno = 0;

    // Iterate through the file by block size
    hmac_init(hctx, key, key_len, NULL);
    while ((bytes_read = fread(buffer, 1, FILE_BUFFER_SIZE, fp)) > 0) {
        hmac_update(hctx, buffer, bytes_read);
    }
    if (ferror(fp)) {
        rv = KPEP_R_FILE_UNEXPECTED;
        clearerr(fp);
        goto err;
    }
    hmac_final(hctx, mac, NULL, KPEP_GLOBAL_DIGEST_SIZE);
    *mac_len = KPEP_GLOBAL_DIGEST_SIZE;

    // If we got here, rv is still zero and we have SUCCESS!

err:
    if (fp) fclose(fp);
    kpep_cleanse(buffer, FILE_BUFFER_SIZE);  // Zeroize; NULL safe
    hmac_ctx_free(hctx);                     // Zeroize; NULL safe
    return rv;
}
