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

#include <strings.h>
#include <signal.h>

#include "openssl/e_os2.h"

#if defined(OPENSSL_SYS_UNIX)
# include <unistd.h>
#elif defined(OPENSSL_SYS_WINDOWS)
# include <windows.h>
#endif

//  Includes
#include "app_common.h"  //  Includes <stdlib.h>, <stdio.h>, and <string.h>
#include "kpep/kpep.h"

static volatile sig_atomic_t g_keep_running = 1;

static void handle_signal(int sig)
{
	(void)sig;
	g_keep_running = 0;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * USAGE
 * ************************************************************************************************
 * ***********************************************************************************************/

void print_usage(const char* appname)
{
	const int indent = 20;
	printf("%s [-v] [--verbose] [--size <integer>] [--interval <integer>] [--prov <name>]\n", appname);
	printf("%*s [--impl <name>] [--algo <name>] [--propq <string>]\n", (int)strlen(appname), "");
	printf("\n");
	printf("Generate a random number using a method specified by the command line arguments. If no arguments\n");
	printf("are provided, the value will be retrieved by a call to RAND_bytes_ex() with OpenSSL's selection\n");
	printf("of provider.  Additional arguments can select a provider, a different call interface, or specify \n");
	printf("parameter information for the selected interface.\n");
	printf("\n");
	printf("Arguments for RAND_bytes_ex() interface:\n");
	printf("%-*s%s\n", indent, "--prov <name>", "Specify the provider to use with RAND_bytes_ex().  This method only works");
	printf("%-*s%s\n", indent, "",              "with providers that implement the 'OSSL_FUNC_PROVIDER_RANDOM_BYTES' function");
	printf("%-*s%s\n", indent, "",              "as defined in their provider dispatch table.  The 'fips' and 'kpep' providers");
	printf("%-*s%s\n", indent, "",              "implement this, but the 'default' and 'base' providers do not.");
	printf("\n");
	printf("Arguments for EVP_RAND_* interface:\n");
	printf("%-*s%s\n", indent, "--impl <name>", "Use the EVP_RAND_* interface and fetch the specified implementation.");
	printf("%-*s%s\n", indent, "",              "Examples: \"SEED-SRC\", \"KPEP-SEED\", \"CTR-DRBG\", \"HMAC-DRBG\", \"HASH-DRBG\"");
	printf("%-*s%s\n", indent, "--algo <name>", "Specify the algorithm for the specified implementation.  Any valid string");
	printf("%-*s%s\n", indent, "",              "will be used in the fetch.  This argument may or may not be required; this");
	printf("%-*s%s\n", indent, "",              "is implementation-dependent.  It is required for all '*-DRBG' type");
	printf("%-*s%s\n", indent, "",              "implementations, from one of the following selections:");
	printf("%-*s%s\n", indent, "",              "  \"AES-128-CTR\", \"AES-192-CTR\", \"AES-256-CTR\",");
	printf("%-*s%s\n", indent, "",              "  \"SHA3-224\", \"SHA3-256\", \"SHA3-384\", \"SHA3-512\",");
	printf("%-*s%s\n", indent, "",              "  \"SHA2-224\", \"SHA2-256\", \"SHA2-384\", \"SHA2-512\",");
	printf("%-*s%s\n", indent, "",              "  \"SHA2-512/224\", \"SHA2-512/256\",  \"SHA1\"");
	printf("%-*s%s\n", indent, "--propq <name>", "Specify the properties for the fetch query.  Using quoted strings is advised.");
	printf("%-*s%s\n", indent, "",              "Examples: \"fips=yes\", \"?fips=no\", \"provider=kpep\"");
	printf("\n");
	printf("Arguments for all interfaces:\n");
	printf("%-*s%s\n", indent, "--size <integer>", "Specify the number of bytes to retrieve (default 32)");
	printf("%-*s%s\n", indent, "--interval <sec>", "Loop continuously until stopped (e.g. Ctrl-C), sleeping specified seconds between iterations");
	printf("%-*s%s\n", indent, "--verbose, -v", "Output additional information about the operation");
	printf("\n");
}

/* ************************************************************************************************
 * ************************************************************************************************
 * Global Defs
 * ************************************************************************************************
 * ***********************************************************************************************/

// Buffer for random bytes
static size_t   buflen = 32;
static uint8_t *buffer = NULL;

// Pointers to argv[] strings
static const char *prov_arg = NULL;
static const char *impl_arg = NULL;
static const char *algo_arg = NULL;
static const char *propq_arg = NULL;

static uint32_t verbose = 0;

static const char *allowed_ctr[] = {
	"AES-128-CTR", "AES-192-CTR", "AES-256-CTR", 
	NULL
};

static const char *allowed_hash[] = {
	"SHA1",
	"SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-512/224", "SHA2-512/256",
	"SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
	NULL
};

/* ************************************************************************************************
 * ************************************************************************************************
 * MAIN
 * ************************************************************************************************
 * ***********************************************************************************************/

#ifdef _NONFIPS_MODE
static uint32_t do_public_api(void);
#endif
static uint32_t do_openssl_api(void);

static int found_in(const char *haystack[], const char *needle) 
{
	const char* ptr;
	int32_t idx = 0;

	if (!haystack || !needle)
		return 0;
	
	ptr = haystack[idx];
	while (ptr) {
		if (!strcmp(ptr, needle))
			return 1;
		ptr = haystack[++idx];
	}
	printf("Could not find '%s' in the allowed set of value.  Please choose from one of the following:\n", needle);
	idx = 0;
	ptr = haystack[idx];
	while (ptr) {
		printf("\t%s\n", ptr);
		ptr = haystack[++idx];
	}
	return 0;
}

int main(int argc, char* argv[]) 
{
	int ind = 1;
	uint32_t openssl = 1;
	uint32_t gathered = 0;
	int interval = 0;

	int32_t tmp;

	// Help?
	if ((argc >= 2) && (0 == strncmp(argv[ind], "--help", 6))) {
		print_usage(argv[0]);
		return 0;
	}

	while  (ind < argc) {
		// VERBOSE
		if (0 == strncmp(argv[ind], "-v", 2)) {
			char* p = argv[ind];
			while (*++p == 'v')
				verbose += 1;
		}
		else if (0 == strncmp(argv[ind], "--verbose", 9)) {
			verbose += 1;
		}
		// ARGUMENTS
		else if (0 == strncmp(argv[ind], "--size", 6)) {
			if ((argc <= ind+1) || (argv[ind+1][0]=='-')) {
				printf("Argument '--size' requires an additional argument with the number of bytes to retrieve\n");
				return 1;
			}
			tmp = atoi(argv[++ind]);
			if (tmp > 0)
				buflen = tmp;
		}
		else if (0 == strncmp(argv[ind], "--interval", 10)) {
			if ((argc <= ind+1) || (argv[ind+1][0]=='-')) {
				printf("Argument '--interval' requires an additional argument with the sleep interval in seconds\n");
				return 1;
			}
			tmp = atoi(argv[++ind]);
			if (tmp > 0)
				interval = tmp;
			else {
				printf("Argument '--interval' requires a positive integer value\n");
				return 1;
			}
		}
		else if (0 == strncmp(argv[ind], "--prov", 6)) {
			if ((argc <= ind+1) || (argv[ind+1][0]=='-')) {
				printf("Argument '--prov' requires an additional argument with the name of the provider to query (e.g. 'kpfp').\n");
				return 1;
			}
			prov_arg = argv[++ind];
		}
		else if (0 == strncmp(argv[ind], "--impl", 6)) {
			if ((argc <= ind+1) || (argv[ind+1][0]=='-')) {
				printf("Argument '--impl' requires an additional argument with the name of the implementation to fetch (e.g. 'HASH-DRBG' or '-SEED')\n");
				return 1;
			}
			impl_arg = argv[++ind];
		}
		else if (0 == strncmp(argv[ind], "--algo", 6)) {
			if ((argc <= ind+1) || (argv[ind+1][0]=='-')) {
				printf("Argument '--algo' requires an additional argument with the name of the DRBG subtype to fetch (e.g. 'SHA2-256').\n");
				return 1;
			}
			algo_arg = argv[++ind];
		}
		else if (0 == strncmp(argv[ind], "--propq", 7)) {
			if ((argc <= ind+1) || (argv[ind+1][0]=='-')) {
				printf("Argument '--propq' requires an additional argument with the string for the fetch properties (e.g. 'fips=yes').\n");
				return 1;
			}
			propq_arg = argv[++ind];
		}

		// Next Argument
		ind++;
	}

	// DRBG-IMPLEMENTATION based?
	if (impl_arg && strstr(impl_arg, "DRBG")) {
		if (strstr(impl_arg, "CTR") && 
			!found_in(allowed_ctr, algo_arg)) {
			return 1;
		}
		if ((strstr(impl_arg, "HASH") || strstr(impl_arg, "HMAC")) && 
			!found_in(allowed_hash, algo_arg)) {
			return 1;
		}
	}

	// Create buffer
	buffer = calloc(buflen, 1);
	if (!buffer) {
		printf("Could not allocate buffer for random bytes\n");
		return 1;
	}

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	do {
		// Get the random bytes
		gathered = do_openssl_api();

		// Each mode prints its own errors.  We only print on good results
		if (gathered > 0) {
			print_hex(NULL, 0, buffer, buflen);
		}

		if (interval > 0 && g_keep_running) {
			int elapsed_sec = 0;
			while (elapsed_sec < interval && g_keep_running) {
#if defined(OPENSSL_SYS_WINDOWS)
				Sleep(1000);
#else
				sleep(1);
#endif
				elapsed_sec++;
			}
		}
	} while (interval > 0 && g_keep_running);

	if (buffer)
		free(buffer);
	return 0;
}

/* ************************************************************************************************
 * OpenSSL API
 * ***********************************************************************************************/
 
#include "app_openssl.h"  // Includes params.h and err.h
#include "openssl/evp.h"
#include "openssl/provider.h"
#include "openssl/rand.h"
#include "openssl/core_names.h"

void recurse_openssl_error(void) 
{
	unsigned long err = 0;
	while (1) {
		err = ERR_get_error();
		if (err < 1) break;
		fprintf(stderr, "OpenSSL error: [%ld] %s\n", err, ERR_reason_error_string(err));
	}
}

static int32_t get_impl_bytes(void);

static uint32_t do_openssl_api(void)
{
	int32_t result = 0;
	OSSL_PROVIDER *prov = NULL;

	// Load implementation or use RAND_*
	if (impl_arg)
		result = get_impl_bytes();
	else {
		if (prov_arg) {
			if (verbose)
				printf("Attempting to load provider '%s':\n", prov_arg);
			prov = OSSL_PROVIDER_load(NULL, prov_arg);
			if (!prov) {
				printf("Could not load the provider '%s' for RAND.\n", prov_arg);
				return 0;
			}
			if (!RAND_set1_random_provider(NULL, prov)) {
				printf("Could not set the provider '%s' as private source.\n", prov_arg);
				goto err;  // Will free prov
			}
			if (verbose) 
				printf("Provider set as source provider for RAND_*\n");
		}
		result = RAND_bytes_ex(NULL, buffer, buflen, 256);
	}

	// Check results
	if (verbose) 
		printf("Result: %d\n", result);
	if (result == 0) {
		recurse_openssl_error();
	}
	else if (result < 0) {
		printf("Not supported by current RAND method\n");
		result = 0; 
	}

err:
	// Cleanup and exit
	if (prov) {
		RAND_set1_random_provider(NULL, NULL);
		OSSL_PROVIDER_unload(prov);
	}
	return result;
}
 
static int32_t get_impl_bytes(void)
{
	int32_t result = 0;

    EVP_RAND *rand = NULL;
    EVP_RAND_CTX *rctx = NULL;

	rand = EVP_RAND_fetch(NULL, impl_arg, propq_arg);
	rctx = EVP_RAND_CTX_new(rand, NULL);
	if (!rctx) {
		printf("Error creating DRBG ctx\n");
		recurse_openssl_error();
		goto err;
	}

	if (verbose) {
		const OSSL_PROVIDER *prov = EVP_RAND_get0_provider(rand);
		if (prov)
			printf("EVP_RAND impl provider: '%s'.\n", OSSL_PROVIDER_get0_name(prov));
		else
			printf("Could not retrieve name of the provider for the EVP_RAND implementation\n");
	}

	if (NULL != strstr(impl_arg, "DRBG")) {
		OSSL_PARAM params[3] = { OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END };
		OSSL_PARAM *p = params;
		char* algo_type = NULL;

		if (0 == strncmp(impl_arg, "CTR", 3)) {
			algo_type = OSSL_DRBG_PARAM_CIPHER;
		}
		else if (0 == strncmp(impl_arg, "HASH", 4)) {
			algo_type = OSSL_DRBG_PARAM_DIGEST;
		}
		else if (0 == strncmp(impl_arg, "HMAC", 4)) {
			algo_type = OSSL_DRBG_PARAM_DIGEST;
		}
		else {
			printf("Invalid DRBG type (expected 'CTR-DRBG', 'HASH-DRBG', or 'HMAC-DRBG').\n");
			result = -1;
			goto err;
		}
		*p++ = OSSL_PARAM_construct_utf8_string(algo_type, (char*) algo_arg, 0);
		*p++ = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC, "HMAC", 0); // ignored if irrelevant
		if (EVP_RAND_CTX_set_params(rctx, params) != 1) {
			printf("Error setting algorithm for DRBG\n");
			recurse_openssl_error();
			goto err;
		}
	}

	if (EVP_RAND_instantiate(rctx, 128, 0, NULL, 0, NULL) != 1) {
		printf("Error performing RAND instantiate\n");
		recurse_openssl_error();
		goto err;
	}

	if (EVP_RAND_generate(rctx, buffer, buflen, 128, 0, NULL, 0) != 1) {
		printf("Error performing rand generate (1)\n");
		recurse_openssl_error();
		goto err;
	}

	if (EVP_RAND_uninstantiate(rctx) != 1) {
		printf("Error performing rand uninstantiate\n");
		recurse_openssl_error();
		goto err;
	}

	result = buflen;

err:
	EVP_RAND_CTX_free(rctx);
	return result;
}
