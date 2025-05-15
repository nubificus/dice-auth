#include <stdio.h>
#include <stdlib.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <dice_auth.h>

int dice_auth(const char *ca_pem, const char *cert_pem) {
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	X509_STORE *store = X509_STORE_new();
	if (!store) {
		fprintf(stderr, "Error creating X509_STORE.\n");
		return -1;
	}

	BIO *ca_bio = BIO_new_mem_buf(ca_pem, -1);
	if (!ca_bio) {
		fprintf(stderr, "Error creating BIO for CA certificate.\n");
		X509_STORE_free(store);
		return -1;
	}

	X509 *cacert = PEM_read_bio_X509(ca_bio, NULL, 0, NULL);
	BIO_free(ca_bio);
	if (!cacert) {
		fprintf(stderr, "Error reading CA certificate from string.\n");
		X509_STORE_free(store);
		return -1;
	}

	if (X509_STORE_add_cert(store, cacert) != 1) {
		fprintf(stderr, "Error adding CA certificate to store.\n");
		X509_free(cacert);
		X509_STORE_free(store);
		return -1;
	}
	X509_free(cacert);

	BIO *cert_bio = BIO_new_mem_buf(cert_pem, -1);
	if (!cert_bio) {
		fprintf(stderr, "Error creating BIO for certificate to verify.\n");
		X509_STORE_free(store);
		return -1;
	}

	X509 *cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
	BIO_free(cert_bio);
	if (!cert) {
		fprintf(stderr, "Error reading certificate to verify from string.\n");
		X509_STORE_free(store);
		return -1;
	}

	X509_STORE_CTX *ctx = X509_STORE_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Error creating X509_STORE_CTX.\n");
		X509_free(cert);
		X509_STORE_free(store);
		return -1;
	}
	if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1) {
		fprintf(stderr, "Error initializing X509_STORE_CTX.\n");
		X509_STORE_CTX_free(ctx);
		X509_free(cert);
		X509_STORE_free(store);
		return -1;
	}

	X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
	if (!param) {
		fprintf(stderr, "Error getting verification parameters.\n");
		X509_STORE_CTX_free(ctx);
		X509_free(cert);
		X509_STORE_free(store);
		return -1;
	}
	X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_IGNORE_CRITICAL);

	int ret = X509_verify_cert(ctx);
	if (ret == 1) {
		;
	} else {
		int err = X509_STORE_CTX_get_error(ctx);
		fprintf(stderr, "Certificate verification failed: %s\n", 
		X509_verify_cert_error_string(err));
	}

	X509_STORE_CTX_free(ctx);
	X509_free(cert);
	X509_STORE_free(store);
	EVP_cleanup();
	ERR_free_strings();

	fflush(stdout);
	fflush(stderr);
	return (ret == 1) ? 0 : -1;
}

