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

#include "ardent/ardent.h"
#include "ardent_internal.h"
#include "ardent_integrity.h"

/* ************************************************************************************************
 * ************************************************************************************************
 * GENERATE HMAC
 * ************************************************************************************************
 * ***********************************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "internal/e_os.h"
#ifndef OPENSSL_SYS_WINDOWS
# include <unistd.h>
#endif
#include "crypto/hmac.h"

/* Fallback definitions for file mode masks if missing in strict ANSI mode */
#ifndef S_IFMT
# define S_IFMT 0170000
#endif
#ifndef S_IFREG
# define S_IFREG 0100000
#endif
#ifndef S_IFDIR
# define S_IFDIR 0040000
#endif
#ifndef S_IFCHR
# define S_IFCHR 0020000
#endif

EXPORT_VISIBILITY_HIDDEN
const unsigned char ardent_integrity_key[] = { 
	0x52, 0x61, 0x6D, 0x64, 0x6F, 0x6D,             // Random
	0x46, 0x72, 0x65, 0x71, 0x75, 0x65, 0x6E, 0x74, // Frequent
	0x46, 0x6C, 0x79, 0x65, 0x72,                   // Flyer
	0x44, 0x65, 0x6E, 0x74                          // Dent
};
EXPORT_VISIBILITY_HIDDEN
const size_t ardent_integrity_key_len = sizeof(ardent_integrity_key);

#define FILE_BUFFER_SIZE 4096

/* Return: NULL if regular file, else brief error message */
static const char* is_valid_file(const char *filename)
{
	struct stat st;

#ifdef OPENSSL_SYS_WINDOWS
	if (0 != stat(filename, &st)) {
		return "stat failed, probably no such file";
	}
#else
	if (0 != lstat(filename, &st)) {
		return "lstat failed, probably no such file";
	}
#endif

	switch (st.st_mode & S_IFMT) {
#ifdef S_IFLNK
	case S_IFLNK:
#endif
	case S_IFREG:
		return NULL;
#ifdef S_IFSOCK
	case S_IFSOCK:
		return "socket";
#endif
#ifdef S_IFBLK
	case S_IFBLK:
		return "block device";
#endif
	case S_IFDIR:
		return "directory";
	case S_IFCHR:
		return "character device";
#ifdef S_IFIFO
	case S_IFIFO:
		return "FIFO";
#endif
	}
	return NULL;
}

EXPORT_VISIBILITY_HIDDEN
ARDENT_RESULT integrity_check_file(const char* filename, 
                            	 const unsigned char *key, size_t key_len,
                            	 unsigned char *mac, size_t *mac_len) 
{
    ARDENT_RESULT rv = ARDENT_R_SUCCESS; // Assume success

    FILE *fp = NULL;
    unsigned char *buffer = NULL;
    size_t bytes_read = 0;

    HMAC_CTX *hctx;

    // Validate arguments
    if (!mac) {
        if (mac_len) {
            *mac_len = ARDENT_GLOBAL_DIGEST_SIZE;
            return ARDENT_R_SUCCESS; // ok
        }
        else 
            return ARDENT_R_NULL_ARG;  // !mac and !mac_len... what do you want?
    }

    if (!filename || !mac_len || *mac_len < ARDENT_GLOBAL_DIGEST_SIZE) {
        return ARDENT_R_INVALID_ARG;
    }
    if (is_valid_file(filename) != NULL) {
        return ARDENT_R_FILE_NOT_VALID;
    }

    // Default Key
    if (!key || !key_len) {
        key = (unsigned char*) ardent_integrity_key;
        key_len = ardent_integrity_key_len;
    }

    // Open file
    fp = fopen(filename, "rb");
    if (!fp) {
        switch (errno) {
            case EACCES:
                rv = ARDENT_R_FILE_BAD_PERMISSIONS;
                break;
            case ENOENT:
                rv = ARDENT_R_FILE_NOT_FOUND;
                break;
            default:
                rv = ARDENT_R_FILE_UNEXPECTED;
        }
        goto err;
    }

    // Initialize the HMAC
    hctx = hmac_ctx_new();
    if (!hctx) {
        rv = ARDENT_R_MALLOC_FAIL;
        goto err;
    }

    // Initialize the read buffer
    buffer = ardent_zalloc(FILE_BUFFER_SIZE);
    if (!buffer) {
        rv = ARDENT_R_MALLOC_FAIL;
        goto err;
    }

    // Reset error before file operations (no POSIX guarantee that errno is set on a file error)
    clearerr(fp);
    errno = 0;

    // Iterate through the file by block size
    if (!hmac_init(hctx, key, key_len, NULL)) {
        rv = ARDENT_R_INTEGRITY_FAIL;
        goto err;
    }
    while ((bytes_read = fread(buffer, 1, FILE_BUFFER_SIZE, fp)) > 0) {
        if (!hmac_update(hctx, buffer, bytes_read)) {
            rv = ARDENT_R_INTEGRITY_FAIL;
            goto err;
        }
    }
    if (ferror(fp) || !feof(fp)) {
        rv = ARDENT_R_FILE_UNEXPECTED;
        clearerr(fp);
        goto err;
    }
    if (!hmac_final(hctx, mac, NULL, ARDENT_GLOBAL_DIGEST_SIZE)) {
        rv = ARDENT_R_INTEGRITY_FAIL;
        goto err;
    }
    *mac_len = ARDENT_GLOBAL_DIGEST_SIZE;

    // If we got here, rv is still zero and we have SUCCESS!

err:
    if (fp) fclose(fp);
    ardent_cleanse(buffer, FILE_BUFFER_SIZE);  // Zeroize; NULL safe
    hmac_ctx_free(hctx);                     // Zeroize; NULL safe
    return rv;
}
