#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <openssl/pem.h>
#include <openssl/err.h>
#include <dice/dice.h>
#include <dice/ops.h>

#define DICE_CODE_SIZE DICE_HASH_SIZE
#define DICE_CONFIG_SIZE DICE_INLINE_CONFIG_SIZE
#define DICE_AUTHORITY_SIZE DICE_HASH_SIZE
#define DICE_MODE_SIZE 1

#define DER_BUF_LEN 2048

DiceResult generate_uds_cert(void* context,
			     const uint8_t current_cdi_attest[DICE_CDI_SIZE],
			     const DiceInputValues *input_values,
			     size_t next_cdi_certificate_buffer_size,
			     uint8_t *next_cdi_certificate,
			     size_t *next_cdi_certificate_actual_size)
{
	// This implementation serializes the inputs for a one-shot hash. On some
	// platforms, using a multi-part hash operation may be more optimal. The
	// combined input buffer has this layout:
	// ---------------------------------------------------------------------------
	// | Code Input | Config Input | Authority Input | Mode Input | Hidden Input |
	// ---------------------------------------------------------------------------
	const size_t kCodeOffset = 0;
	const size_t kConfigOffset = kCodeOffset + DICE_CODE_SIZE;
	const size_t kAuthorityOffset = kConfigOffset + DICE_CONFIG_SIZE;
	const size_t kModeOffset = kAuthorityOffset + DICE_AUTHORITY_SIZE;
	const size_t kHiddenOffset = kModeOffset + DICE_MODE_SIZE;

	DiceResult result = kDiceResultOk;

	// Declare buffers that get cleaned up on 'goto out'.
	uint8_t input_buffer[DICE_CODE_SIZE + DICE_CONFIG_SIZE +
			     DICE_AUTHORITY_SIZE + DICE_MODE_SIZE +
			     DICE_HIDDEN_SIZE];
	uint8_t attest_input_hash[DICE_HASH_SIZE];
	uint8_t current_cdi_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE];

	// Assemble the input buffer.
	memcpy(&input_buffer[kCodeOffset], input_values->code_hash, DICE_CODE_SIZE);
	if (input_values->config_type == kDiceConfigTypeInline) {
		memcpy(&input_buffer[kConfigOffset], input_values->config_value,
		       DICE_CONFIG_SIZE);
	} else if (!input_values->config_descriptor) {
		result = kDiceResultInvalidInput;
		goto out;
	} else {
		result = DiceHash(context, input_values->config_descriptor,
				  input_values->config_descriptor_size,
				  &input_buffer[kConfigOffset]);
		if (result != kDiceResultOk)
		goto out;
	}
	memcpy(&input_buffer[kAuthorityOffset], input_values->authority_hash,
	       DICE_AUTHORITY_SIZE);
	input_buffer[kModeOffset] = input_values->mode;
	memcpy(&input_buffer[kHiddenOffset], input_values->hidden,
	       DICE_HIDDEN_SIZE);

	result =
		DiceHash(context, input_buffer, sizeof(input_buffer),
			 attest_input_hash);
	if (result != kDiceResultOk)
		goto out;

	// Create the CDI certificate only if it is required (i.e. non-null/non-zero
	// values are provided for the next CDI certificate parameters).
	if (next_cdi_certificate == NULL &&
	    next_cdi_certificate_actual_size == NULL &&
	    next_cdi_certificate_buffer_size == 0)
		goto out;

	// Derive asymmetric private key seeds from the attestation CDI values.
	result = DiceDeriveCdiPrivateKeySeed(context, current_cdi_attest,
					     current_cdi_private_key_seed);
	if (result != kDiceResultOk)
		goto out;

	// Generate self signed cert for current_cdi_private_key_seed,
	result = DiceGenerateCertificate(context, current_cdi_private_key_seed,
					 current_cdi_private_key_seed,
					 input_values,
					 next_cdi_certificate_buffer_size,
					 next_cdi_certificate,
					 next_cdi_certificate_actual_size);

out:
	// Clear sensitive memory.
	DiceClearMemory(context, sizeof(input_buffer), input_buffer);
	DiceClearMemory(context, sizeof(attest_input_hash), attest_input_hash);
	DiceClearMemory(context, sizeof(current_cdi_private_key_seed),
			current_cdi_private_key_seed);
	return result;
}

int der_to_pem_buffer(const unsigned char *der_buf, size_t der_len, char **pem_buf, size_t *pem_len) {
	X509 *cert = NULL;
	BIO *pem_bio = NULL;
	BUF_MEM *pem_mem = NULL;

	const unsigned char *p = der_buf;
	cert = d2i_X509(NULL, &p, der_len);
	if (!cert) {
		fprintf(stderr, "Error reading DER buffer\n");
		ERR_print_errors_fp(stderr);
		return 1;
	}

	pem_bio = BIO_new(BIO_s_mem());
	if (!pem_bio) {
		fprintf(stderr, "Error creating BIO for PEM data\n");
		ERR_print_errors_fp(stderr);
		X509_free(cert);
		return 1;
	}

	if (!PEM_write_bio_X509(pem_bio, cert)) {
		fprintf(stderr, "Error writing PEM data to BIO\n");
		ERR_print_errors_fp(stderr);
		BIO_free(pem_bio);
		X509_free(cert);
		return 1;
	}

	BIO_get_mem_ptr(pem_bio, &pem_mem);
	*pem_len = pem_mem->length;

	*pem_buf = (char *)malloc(*pem_len + 1);
	if (!*pem_buf) {
		fprintf(stderr, "Error allocating memory for PEM buffer\n");
		BIO_free(pem_bio);
		X509_free(cert);
		return 1;
	}

	memcpy(*pem_buf, pem_mem->data, *pem_len);
	(*pem_buf)[*pem_len] = '\0';

	BIO_free(pem_bio);
	X509_free(cert);

	return 0;
}

static const uint8_t asym_salt[] = {
	0x63, 0xB6, 0xA0, 0x4D, 0x2C, 0x07, 0x7F, 0xC1, 0x0F, 0x63, 0x9F,
	0x21, 0xDA, 0x79, 0x38, 0x44, 0x35, 0x6C, 0xC2, 0xB0, 0xB4, 0x41,
	0xB3, 0xA7, 0x71, 0x24, 0x03, 0x5C, 0x03, 0xF8, 0xE1, 0xBE, 0x60,
	0x35, 0xD3, 0x1F, 0x28, 0x28, 0x21, 0xA7, 0x45, 0x0A, 0x02, 0x22,
	0x2A, 0xB1, 0xB3, 0xCF, 0xF1, 0x67, 0x9B, 0x05, 0xAB, 0x1C, 0xA5,
	0xD1, 0xAF, 0xFB, 0x78, 0x9C, 0xCD, 0x2B, 0x0B, 0x3B};

int der_root_from_uds(char *root, uint8_t *uds)
{
	DiceResult ret;
	uint8_t uds_buffer[DICE_PRIVATE_KEY_SEED_SIZE] = {0};
	DiceInputValues input_values = {0};
	uint8_t cert_buffer[2048];
	size_t cert_size;

	ret = DiceKdf(NULL, DICE_PRIVATE_KEY_SEED_SIZE, uds,
		      6, asym_salt, sizeof(asym_salt),
		      (const uint8_t*)"UDS hkdf", 8, uds_buffer);
	if (ret != kDiceResultOk) {
		fprintf(stderr, "DICE HKDF failed!");
		return -1;
	}

	ret = generate_uds_cert(NULL, uds_buffer, &input_values,
				sizeof(cert_buffer), cert_buffer, &cert_size);
	if (ret != kDiceResultOk) {
		fprintf(stderr,"DICE UDS creation failed!");
		return -1;
	}
	memcpy(root, cert_buffer, cert_size);
	return (int) cert_size;
}

typedef enum mode {
        DICE_PEM = 0,
        DICE_DER
} out_mode;
int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s unique_device_secret [--pem]\n", argv[0]);
		return 1;
	}

	const char *mac_uds  = argv[1];
	uint8_t mac[6] = { 0 };
	size_t der_len;
	char der_root[DER_BUF_LEN] = { 0 };
	char *pem_root = NULL;
	size_t pem_len;
        char *output = NULL;
        size_t *output_len = NULL;
        out_mode output_mode;

        if (argc == 3 && strcmp(argv[2], "--pem") == 0) {
                output_mode = DICE_DER;
        } else {
                output_mode = DICE_DER;
        }
                
	sscanf(mac_uds, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0],
	       &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

	fprintf(stderr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", mac[0],
	       mac[1], mac[2], mac[3], mac[4], mac[5]);

	der_len = der_root_from_uds(der_root, mac);
	if (der_len <= 0) {
		fprintf(stderr, "Could not generate root certificate\n");
		return -1;
	}

	if (der_to_pem_buffer((const unsigned char *) der_root,
			      der_len, &pem_root, &pem_len) != 0) {
		fprintf(stderr, "Conversion failed\n");
		return -1;
	}
        if (output_mode == DICE_PEM) {
                output = pem_root;
                output_len = &pem_len;
        } else {
                output = der_root;
                output_len = &der_len;
        }

	fwrite(output, 1, *output_len, stdout);
	return 0;
}

