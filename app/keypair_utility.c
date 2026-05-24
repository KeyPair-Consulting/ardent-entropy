/* ************************************************************************************************
 * Copyright (C) 2022-2025 Symbiotic Systems Research, LLC
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

//  Includes
#include "app_common.h"  //  Includes <stdlib.h>, <stdio.h>, and <string.h>
#include "kpep/kpep.h"
#include "../source/integrity.h"

// OpenSSL Includes
#include "app_openssl.h"  // Includes params.h and err.h
#include "openssl/provider.h"
#include "openssl/core_names.h"
#include "openssl/evp.h"
#include "openssl/self_test.h"

/* ************************************************************************************************
 * ************************************************************************************************
 * USAGE
 * ************************************************************************************************
 * ***********************************************************************************************/

void print_usage(const char* appname)
{
	int len = strlen(appname);
	printf("%*s [--info <provider-name>]\n", len, appname);
	printf("%*s [--cast <provider-name>]\n", len, "");
	printf("%*s [--fetch-* [OPTIONS] ]\n", len, "");
	printf("%*s [--mac <filename>]\n", len, "");
	printf("%*s [-v]\n", len, "");
	printf("\n");
	printf("This utility performs several helpful operations in conjunction with the KeyPair Management Provider ().\n");
	printf("Only one operation will be performed for each invocation of the binary.\n");
	printf("\n");
	printf("OP: PROVIDER INFORMATION\n");
	printf("Query an OpenSSL Provider for information\n");
	printf("\n");
	printf("  %-24s%s\n", "--info <provider-name>", "Query the named provider for info and configuration");
	printf("\n");
	printf("OP: PROVIDER SELF-TEST\n");
	printf("Cause an OpenSSL Provider to perform the Cryptographic Algorithm Self-Tests (CASTs)\n");
	printf("\n");
	printf("  %-24s%s\n", "--cast <provider-name>", "Cause the named provider to perform CASTs");
	printf("\n");
	printf("OP: FETCH AN ALGORITHM AND REPORT PROVIDER NAME\n");
	printf("Fetch a named algorithm and report the name of the provider implementation\n");
	printf("\n");
	printf("  %-24s%s\n", "--fetch-hash <hash-algo> <properties>", "");
	printf("  %-24s%s\n", "", "Fetch the named hash algorithm using the provided properties string");
	printf("  %-24s%s\n", "", "Example: --fetch-hash SHA3-256 \"provider=kpfp\"");
	printf("  %-24s%s\n", "--fetch-cipher <hash-algo> <properties>", "");
	printf("  %-24s%s\n", "", "Fetch the named cipher algorithm using the provided properties string");
	printf("  %-24s%s\n", "", "Example: --fetch-cipher AES-256-CBC \"fips=yes\"");
	printf("\n");
	printf("OP: FILE HMAC\n");
	printf("Generate a FIPS 140-3 HMAC integrity file for a named file\n");
	printf("\n");
	printf("  %-24s%s\n", "--mac <filename>", "Generate an HMAC-SHA2-256 of the named file and write to a file.  This is used");
	printf("  %-24s%s\n", "", "exclusively for the creation of FIPS 140-3 integrity files. Use the 'kpep_filecheck'");
	printf("  %-24s%s\n", "", "app for a general solution to file integrity and verification.");
	printf("\n");
	printf("GENERAL\n");
	printf("  %-24s%s\n", "-v", "Add verbose output about progress");
	printf("\n");
}

/* ************************************************************************************************
 * ************************************************************************************************
 * PROVIDER STUFF
 * ************************************************************************************************
 * ***********************************************************************************************/

static OSSL_PROVIDER* get_provider(OSSL_LIB_CTX *libctx, const char* provider_name, int verbose)
{
	OSSL_PROVIDER *prov = NULL;

	/* Check availability */
	if (!OSSL_PROVIDER_available(libctx, provider_name)) {
		printf("Provider '%s' could not be found.\n", provider_name);
		ERR_print_errors_fp(stdout);
		return NULL;
	}
	if (verbose)
		printf("Provider '%s' is available.\n", provider_name);
	
	/* Get a handle to the provider */
	prov = OSSL_PROVIDER_load(libctx, provider_name);
	if (!prov) {
		printf("Provider '%s' could not be loaded.\n", provider_name);
		ERR_print_errors_fp(stdout);
		return NULL;
	}
	if (verbose)
		printf("Provider '%s' is loaded.\n", provider_name);

	return prov;
}

/* ************************************************************************************************
 * PROVIDER INFO
 * ***********************************************************************************************/

static char* data_type_str[] = {
	 "NULL/DUMMY"
	,"OSSL_PARAM_INTEGER"
	,"OSSL_PARAM_UNSIGNED_INTEGER"
	,"OSSL_PARAM_REAL"
	,"OSSL_PARAM_UTF8_STRING"
	,"OSSL_PARAM_OCTET_STRING"
	,"OSSL_PARAM_UTF8_PTR"
	,"OSSL_PARAM_OCTET_PTR"
};

/* Structure to glue an OSSL_PARAMS to a backing data structure */
typedef struct ossl_param_data_st {
	OSSL_PARAM *param;
	union {
		int ints;
		unsigned int uints;
		double dbls;
		char* ptr;
	} data;
} OSSL_PARAM_DATA;

static int query_provider(OSSL_PROVIDER *prov, int verbose) 
{
	int result = 0;

	const OSSL_PARAM *gettable = NULL, *g = NULL;
	OSSL_PARAM       *params = NULL, *p = NULL;
	unsigned int pcount = 0;
	unsigned int col_width = 0;

	/* An array of these is create to back each OSSL_PARAM at the same index */
	OSSL_PARAM_DATA *data = NULL, *d = NULL;

	const char* name = OSSL_PROVIDER_get0_name(prov);

	/* Get the list of 'gettable' parameters */
	gettable = g = (const OSSL_PARAM*) OSSL_PROVIDER_gettable_params((void *) prov);
	while (g->data_type) {
		if (col_width < strlen(g->key))
			col_width = strlen(g->key);
		pcount++;
		g++;
	}
	if (verbose) 
		printf("Provider reports %d available parameters.\n", pcount);

	/* Allocate memory for the parameter values */
	pcount++; /* One extra param for the endcap */
	params = calloc(pcount, sizeof(OSSL_PARAM));
	if (!params) {
		printf("Failed to allocate memory for parameter structures.\n");
		return 1;
	}
	data = calloc(pcount, sizeof(OSSL_PARAM_DATA));
	if (!data) {
		printf("Failed to allocate memory for parameter data.\n");
		free(params);
		return 1;
	}

	/* From here, we need to ensure free() of the params and data arrays */
	/* So.... a poor man's try-finally.  We only 'break' from here, never return. */
	do {
		if ((pcount-1)>0 && verbose > 1) {
			printf("\n");
			printf("%-*s   %s\n", col_width, "PARAM KEY", "DATA TYPE");
			printf("%-*s   %s\n", col_width, "=======================", "========================");
		}
		for (g=gettable, d=data, p=params; g->data_type != 0; g++, d++, p++) {
			d->param = p;
			if (verbose > 1) 
				printf("%-*s : %s\n", col_width, g->key, data_type_str[g->data_type]);
			if (g->data_type == OSSL_PARAM_REAL) {
				*p = OSSL_PARAM_construct_double(g->key, &d->data.dbls);
			}
			else if (g->data_type == OSSL_PARAM_INTEGER) {
				*p = OSSL_PARAM_construct_int(g->key, &d->data.ints);
			}
			else if (g->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
				*p = OSSL_PARAM_construct_uint(g->key, &d->data.uints);
			}
			else if (g->data_type == OSSL_PARAM_UTF8_PTR) {
				*p = OSSL_PARAM_construct_utf8_ptr(g->key, &d->data.ptr, 0);
			}
			else if (g->data_type == OSSL_PARAM_OCTET_PTR) {
				*p = OSSL_PARAM_construct_octet_ptr(g->key, (void**) &d->data.ptr, 0);
			}
			else if (g->data_type == OSSL_PARAM_UTF8_STRING) {
				d->data.ptr = calloc(1,MAX_STRLEN);
				if (!d->data.ptr) {
					printf("Failed to allocate memory for parameter data.\n");
					result = 1;
					break;
				}
				*p = OSSL_PARAM_construct_utf8_string(g->key, d->data.ptr, MAX_STRLEN);
			}
			else if (g->data_type == OSSL_PARAM_OCTET_STRING) {
				d->data.ptr = calloc(1,MAX_STRLEN);
				if (!d->data.ptr) {
					printf("Failed to allocate memory for parameter data.\n");
					result = 1;
					break;
				}
				*p = OSSL_PARAM_construct_octet_string(g->key, d->data.ptr, MAX_STRLEN);
			}
			else {
				printf("Unknown Datatype [%d] for Key '%s'\n", g->data_type, g->key);
			}
		}
		/* Break if error inside the for() */
		if (result) break;
		if (verbose > 1) 
			printf("\n");

		/* Endcap the array correctly */
	    *p = OSSL_PARAM_construct_end();
		d->param = p;

		/* Retrieve the parameters */
		if (!OSSL_PROVIDER_get_params(prov, params)) {
			printf("Provider '%s' could not be loaded.\n", name);
			ERR_print_errors_fp(stdout);
			result = 1;
			break;
		}

		/* Print the parameters */
		if ((pcount-1)>0) {
			if (verbose)
				printf("\n");
			printf("%-*s   %s\n", col_width, "PARAM KEY", "PARAM VALUE");
			printf("%.*s   %s\n", col_width, 
				"========================================", \
				"====================");
		}
		for (d=data; d->param && d->param->data_type > 0; d++) {
			switch (d->param->data_type) {
				case OSSL_PARAM_REAL:
					printf("%-*s : %f\n", col_width, d->param->key, d->data.dbls);
					break;
				case OSSL_PARAM_INTEGER:
					printf("%-*s : %d\n", col_width, d->param->key, d->data.ints);
					break;
				case OSSL_PARAM_UNSIGNED_INTEGER:
					printf("%-*s : %d\n", col_width, d->param->key, d->data.uints);
					break;
				case OSSL_PARAM_UTF8_PTR:
					if (0 == strcmp(d->param->key, KPEP_PROV_PARAM_SEED_SOURCES)) {
						char *tok, buf[SEED_CONTROL_DESCRIPTION_MAX] = { 0 };
						strcpy(buf, d->data.ptr);
						tok = strtok(buf, "\n");
						if (!tok) break;
						printf("%-*s : %s\n", col_width, d->param->key, buf);
						while (NULL != (tok = strtok(NULL, "\n")) ){
							printf("%-*s%s\n", col_width+3, "", tok);
						}
					}
					else {
						printf("%-*s : %s\n", col_width, d->param->key, d->data.ptr);
					}
					break;
				case OSSL_PARAM_OCTET_PTR:
					print_hex(d->param->key, col_width, (unsigned char*)d->data.ptr, d->param->return_size);
					break;
				case OSSL_PARAM_UTF8_STRING:
					printf("%-*s : %s\n", col_width, d->param->key, d->data.ptr);
					free(d->data.ptr);
					break;
				case OSSL_PARAM_OCTET_STRING:
					print_hex(d->param->key, col_width, (unsigned char*)d->data.ptr, d->param->return_size);
					free(d->data.ptr);
					break;
				default:
					/* Ignore */
					break;
			}
		}
	} while (0); // Only once

	/* Cleanup! */
	OPENSSL_free(params);
	OPENSSL_free(data);

	return result;
}

static int provider_info(OSSL_LIB_CTX *libctx, const char* provider_name, int verbose)
{
	int rv;
	OSSL_PROVIDER *prov = NULL;

	prov = get_provider(libctx, provider_name, verbose);
	if (!prov)
		return 1;

	rv = query_provider(prov, verbose);
	return rv;
}


/* ************************************************************************************************
 * PROVIDER CAST
 * ***********************************************************************************************/

typedef struct st_args {
	const char* test_name;
	char* buffer;             // *COPY* of the argument; must be freed
	const char* corrupt_desc; // ptr to 1st token
	const char* corrupt_type; // ptr to 2nd token
	int desc_star;            // Is the desc a star?
	int type_star;            // Is the type a star?
	int suppress_output;      // Flag - Do *NOT* show callback info during test
	int header;               // Flag - Show header only once per test
} SELF_TEST_ARGS;

static SELF_TEST_ARGS self_test_args = { 0 };

static int self_test_events(const OSSL_PARAM params[], void *varg)
{
    SELF_TEST_ARGS *args = varg;
    const OSSL_PARAM *p = NULL;
    const char *phase = NULL, *type = NULL, *desc = NULL;
	const char *phase_name = NULL;
	int corrupt = 0, integrity = 0;
	int skip = 0;

	// Bypass for DRBG test
	if (args->suppress_output)
		return 1;  // Don't print anything

	if (args->header == 0) {
		printf("%-18s %-20s %s\n", "Description", "Type", "Pass/Fail");
		printf("================== ==================== =========\n");
		args->header = 1;
	}

	// Get the Phase
    p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_PHASE);
    if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING)
        return 0; // Fail
    phase = (const char *)p->data;

	// Determine the phase
	if (0 == strncmp(phase, OSSL_SELF_TEST_PHASE_CORRUPT, 7)) {
		corrupt = 1;
	}
	else if (0 == strncmp(phase, OSSL_SELF_TEST_PHASE_PASS, 4)) {
		phase_name = "PASS";
	}
	else if (0 == strncmp(phase, OSSL_SELF_TEST_PHASE_FAIL, 4)) {
		phase_name = "FAIL";
	}
	else if (0 == strncmp(phase, OSSL_SELF_TEST_PHASE_START, 5)) {
		phase_name = "START";
		skip = 1;
	}
	else
		return 1;  // Only accept Pass/Fail/Corrupt

	// Get Desc
    p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_DESC);
    if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING)
        return 0; // Fail
    desc = (const char *)p->data;

	// Get Type
    p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_TYPE);
    if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING)
        return 0; // Fail
    type = (const char *)p->data;
	integrity = !!strstr(type, "Integrity");

	// Do the ask
	// printf("Rec'd: %s : %s : %s\n", desc, type, phase);
	if (skip) goto early;

	if (corrupt) {
		if (args->corrupt_desc && args->corrupt_type) {
			if (   ((args->desc_star)               || (0 == strncmp(desc, args->corrupt_desc, strlen(args->corrupt_desc)))) 
				&& ((args->type_star && !integrity) || (0 == strncmp(type, args->corrupt_type, strlen(args->corrupt_type)))) ) {
				printf("Corrupting: %s : %s\n", args->corrupt_desc, args->corrupt_type);
				return 0;  // Corrupt the answer!
			}
		}
	}
	else {
		// Print Pass/Fail
		if ((0 != strcmp(desc, "None")) && (0 != strcmp(type, "None")))
			printf("%-18s %-20s %s\n", desc, type, phase_name);
	}
early:
    return 1;
}

static int provider_self_test(OSSL_LIB_CTX *libctx, const char* provider_name, int verbose)
{
	int rv;
	OSSL_PROVIDER *prov = NULL;

	// Set callback
    OSSL_SELF_TEST_set_callback(libctx, self_test_events, &self_test_args);

	// Get provider
	self_test_args.suppress_output = 1;   // No output for provider load
	prov = get_provider(libctx, provider_name, verbose);
	if (!prov)
		return 1;

	// Run self-tests
	self_test_args.suppress_output = 0;  // Output for explicit call
	rv = OSSL_PROVIDER_self_test(prov);
	printf("Self Tests: %s\n", rv?"PASSED":"FAILED");
	return rv;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * FETCH ALGORITHM
 * ************************************************************************************************
 * ***********************************************************************************************/

static int fetch_algo(OSSL_LIB_CTX *libctx, 
                      const char *props, 
                      const char *hash_name,
                      const char *cipher_name)
{
	EVP_MD* md = NULL;
	EVP_CIPHER* cipher = NULL;
	const OSSL_PROVIDER *prov = NULL;
	const char *prov_name = NULL;

	if (!hash_name && !cipher_name)
		return 1;
	
	printf("PROPS  : %s\n", props);
	printf("HASH   : %s\n", hash_name);
	printf("CIPHER : %s\n", cipher_name);


	if (hash_name) {
		if ((NULL == (md = EVP_MD_fetch(libctx, hash_name, props))) ||
			(NULL == (prov = EVP_MD_get0_provider(md)))) {
			printf("Failed to fetch hash algorithm '%s'\n", hash_name);
			return 1;
		}
	}
	else {
		if ((NULL == (cipher = EVP_CIPHER_fetch(libctx, cipher_name, props))) ||
			(NULL == (prov = EVP_CIPHER_get0_provider(cipher)))) {
			printf("Failed to fetch cipher algorithm '%s'\n", cipher_name);
			return 1;
		}
	}

	if (NULL == (prov_name = OSSL_PROVIDER_get0_name(prov)))
		return 1;
	
	printf("Algorithm '%s' is implemented by provider \"%s\"\n", 
			(hash_name)?hash_name:cipher_name, prov_name);

	return 0; // Inv. BOOL
}

/* ************************************************************************************************
 * ************************************************************************************************
 * GENERATE HMAC
 * ************************************************************************************************
 * ***********************************************************************************************/

static int generate_mac(OSSL_LIB_CTX *libctx, const char *filename, int verbose)
{
	int rv = KPEP_R_SUCCESS; // Assume success
	int i;
	unsigned char mac[32] = { 0 };
	size_t mac_len = sizeof(mac);
	BIO *bio = NULL;

	const char *prefix = "module-mac = ";
	char       *out_filename;
	size_t      out_filename_len; 

	// Validate
	if (!filename)
		return 0;

	// Do the HMAC
	if ((rv = integrity_check_file(filename, kpep_integrity_key, kpep_integrity_key_len, mac, &mac_len)) != KPEP_R_SUCCESS) {
		printf("Failed to generate the HMAC for file '%s': %s\n", filename, kpep_get_reason_string(rv));
		goto err;		
	}

	// Filename
	out_filename_len = strlen(filename)+5;
	out_filename = kpep_zalloc(out_filename_len);
	if (!out_filename) {
		rv = KPEP_R_MALLOC_FAIL;
		goto err;
	}
	strcpy(out_filename, filename);
	strcat(out_filename, ".mac");

	// Open
	bio = BIO_new_file(out_filename, "w");
	if (bio == NULL) {
		rv = KPEP_R_FILE_FAILED_TO_OPEN;
		printf("Failed to open file '%s' for writing\n", out_filename);
		goto err;
	}

	// Write
	BIO_printf(bio, "%s", prefix);
	for (i=0; i<32; ++i) {
		BIO_printf(bio, "%02X", mac[i]);
		if (i != 31)
			BIO_printf(bio, ":");
	}
	BIO_printf(bio, "\n");
err:
	ERR_print_errors_fp(stdout);
	BIO_free(bio);
	return rv;
}

/* ************************************************************************************************
 * ************************************************************************************************
 * MAIN
 * ************************************************************************************************
 * ***********************************************************************************************/

enum OP_TYPE {
	HELP = 0,
	INFO, 
	CAST,
	HMAC,
	FETCH_HASH,
	FETCH_CIPHER
};

static const char* OP_TYPE_NAMES[] = {
	"--help",
	"--info",
	"--cast",
	"--hmac",
	"--fetch-hash",
	"--fetch-cipher"
};

int main(int argc, char* argv[]) 
{
	int ok = 0, verbose = 0;
	int ind = 1;
	
	const char *out_filename = NULL;
	const char *op_argument = NULL, *op_argument_detail = NULL;
	const char *prefix = NULL;
	char prefix_actual[4098] = { 0 }; // PATH_MAX is typically 4096, plus one char and terminator
	enum OP_TYPE optype = HELP;
	int append = 0, manifest = 0, module = 0;

	if (argc < 2) {
		print_usage(argv[0]);
		return 0;
	}

	/* Process Arguments */
	while  (ind < argc) {
		if (0 == strncmp(argv[ind], "-v", 2)) {
			char* p = argv[ind];
			while (*++p == 'v')
				verbose += 1;
		}
		/* OPERATIONS */
		else if (0 == strncmp(argv[ind], "--help", 6)) {
			print_usage(argv[0]);
			return 0;
		}
		else if (0 == strncmp(argv[ind], "--info", 6)) {
			if (argc <= ind+1) {
				printf("Argument '--info' requires an additional argument with the name of the provider to query\n");
				return 1;
			}
			if (optype != HELP) {
				printf("Multiple operations detected ('--info' and '%s'); Only 1 operation allowed.\n", OP_TYPE_NAMES[optype]);
				return 1;
			}
			optype = INFO;
			op_argument = argv[++ind];
		}
		else if (0 == strncmp(argv[ind], "--cast", 6)) {
			if (argc <= ind+1) {
				printf("Argument '--cast' requires an additional argument with the name of the provider to query\n");
				return 1;
			}
			if (optype != HELP) {
				printf("Multiple operations detected ('--cast' and '%s'); Only 1 operation allowed.\n", OP_TYPE_NAMES[optype]);
				return 1;
			}
			optype = CAST;
			op_argument = argv[++ind];
		}
		else if (0 == strncmp(argv[ind], "--hmac", 5)) {
			if (argc <= ind+1) {
				printf("Argument '--hmac' requires an additional argument with the absolute path of the file to HMAC.\n");
				return 1;
			}
			if (optype != HELP) {
				printf("Multiple operations detected ('--hmac' and '%s'); Only 1 operation allowed.\n", OP_TYPE_NAMES[optype]);
				return 1;
			}
			optype = HMAC;
			op_argument = argv[++ind];
		}
		else if (0 == strncmp(argv[ind], "--fetch-cipher", 14)) {
			if (argc < ind+1) {
				printf("Argument '--fetch-cipher' requires two additional arguments.  See '--help' for more details.\n");
				return 1;
			}
			if (optype != HELP) {
				printf("Multiple operations detected ('--fetch-cipher' and '%s'); Only 1 operation allowed.\n", OP_TYPE_NAMES[optype]);
				return 1;
			}
			optype = FETCH_CIPHER;
			op_argument = argv[++ind];
			op_argument_detail = argv[++ind];
		}
		else if (0 == strncmp(argv[ind], "--fetch-hash", 12)) {
			if (argc <= ind+1) {
				printf("Argument '--fetch-hash' requires two additional arguments.  See '--help' for more details.\n");
				return 1;
			}
			if (optype != HELP) {
				printf("Multiple operations detected ('--fetch-hash' and '%s'); Only 1 operation allowed.\n", OP_TYPE_NAMES[optype]);
				return 1;
			}
			optype = FETCH_HASH;
			op_argument = argv[++ind];
			op_argument_detail = argv[++ind];
		}
		else {
			printf("Unrecognized argument '%s'\n\n", argv[ind]);
			print_usage(argv[0]);
			return 1;
		}
		ind++;
	}

	switch (optype) {
	case HELP:
		print_usage(argv[0]);
		ok = 0;
		break;
	case INFO:
		ok = provider_info(NULL, op_argument, verbose);  // Inv. Bool return
		break;
	case CAST:
		ok = provider_self_test(NULL, op_argument, verbose);  // Inv. Bool return
		break;
	case HMAC:
		ok = generate_mac(NULL, op_argument, verbose);  // Inv. Bool return
		break;
	case FETCH_CIPHER:
		ok = fetch_algo(NULL, op_argument_detail, NULL, op_argument);  // Inv. Bool return
		break;
	case FETCH_HASH:
		ok = fetch_algo(NULL, op_argument_detail, op_argument, NULL);  // Inv. Bool return
		break;		
	default:
		printf("Failoed to recognize operation.\n");
		ok = 1;
	}

	return ok;
}

