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
#include "integrity.h"

/* ************************************************************************************************
 * ************************************************************************************************
 * GENERAL UTILITIES
 * ************************************************************************************************
 * ***********************************************************************************************/

EXPORT_VISIBILITY_DEFAULT
void  kpep_free(void* ptr)
{
	if (!ptr)
		return;
	free(ptr);
}

EXPORT_VISIBILITY_DEFAULT
void  kpep_cleanse(void* ptr, size_t size)
{
	if (!ptr)
		return;
	memset(ptr, 0, size);
	free(ptr);
}

EXPORT_VISIBILITY_DEFAULT
void* kpep_zalloc(size_t size)
{
    uint8_t *buffer = NULL;
    if ((size > 0) && (buffer = malloc(size)) != NULL) {
        memset(buffer, 0, size);
    }
    return buffer;
}

// Stores the trimmed input string into the given output buffer, which must be
// large enough to store the result.  If it is too small, the output is truncated.
// https://stackoverflow.com/questions/122616/how-do-i-trim-leading-trailing-whitespace-in-a-standard-way
EXPORT_VISIBILITY_DEFAULT
size_t kpep_trimwhitespace(char *out, size_t len, const char *str)
{
	const char *end;
	size_t out_size;

	if (len == 0)
		return 0;

	// Trim leading space
	while (isspace((unsigned char)*str)) str++;

	// All spaces?
	if (*str == 0) {
    	*out = 0;
    	return 0;
	}

	// Trim trailing space
	end = str + strlen(str) - 1;
	while(end > str && isspace((unsigned char)*end)) end--;
	end++;

  	// Set output size to minimum of trimmed string length and buffer size minus 1
	out_size = ((size_t) (end - str)) < len-1 ? (size_t) (end - str) : len-1;

	// Copy trimmed string and add null terminator
	memcpy(out, str, out_size);
	out[out_size] = 0;

	return out_size;
}

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
