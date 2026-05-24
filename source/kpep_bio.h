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

#ifndef KPEP_BIO_H
# define KPEP_BIO_H
# pragma once

#include "openssl/bio.h"

# ifdef __cplusplus
extern "C" {
# endif

/* ************************************************************************************************
 * OpenSSL BIO 
 * ***********************************************************************************************/

int kpep_bio_from_dispatch(const OSSL_DISPATCH *fns);

OSSL_CORE_BIO *kpep_bio_new_file(const char *filename, const char *mode);
OSSL_CORE_BIO *kpep_bio_new_membuf(const char *filename, int len);

int kpep_bio_read_ex(OSSL_CORE_BIO *bio, void *data, size_t data_len, size_t *bytes_read);
int kpep_bio_write_ex(OSSL_CORE_BIO *bio, const void *data, size_t data_len, size_t *written);
int kpep_bio_gets(OSSL_CORE_BIO *bio, char *buf, int size);
int kpep_bio_puts(OSSL_CORE_BIO *bio, const char *str);
int kpep_bio_ctrl(OSSL_CORE_BIO *bio, int cmd, long num, void *ptr);
int kpep_bio_up_ref(OSSL_CORE_BIO *bio);
int kpep_bio_free(OSSL_CORE_BIO *bio);
int kpep_bio_vprintf(OSSL_CORE_BIO *bio, const char *format, va_list ap);
int kpep_bio_printf(OSSL_CORE_BIO *bio, const char *format, ...);

BIO_METHOD *kpep_bio_prov_init_bio_method(void);
BIO *kpep_bio_new_from_core_bio(void *provctx, OSSL_CORE_BIO *corebio);

/* END *******************************************************************************************/
# ifdef __cplusplus
}
# endif
#endif /* KPEP_BIO_H */
