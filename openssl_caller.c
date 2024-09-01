#include <stdint.h>
#include <stdbool.h>

#include "wolfssl/openssl/conf.h"
#include "wolfssl/openssl/evp.h"
#include "wolfssl/openssl/err.h"

#include "openssl_caller.h"

static EVP_CIPHER_CTX *ctx;
static bool initialized;

static void handle_errors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

int openssl_aesgcm_init(void)
{
	if (initialized) {
		return 0;
	}

	/* Create and initialise the context */
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		handle_errors();
	}

	initialized = true;
	return 0;
}

int openssl_aesgcm_encrypt(uint8_t *plaintext, uint32_t plaintext_len, uint8_t *aad,
						   uint32_t aad_len, uint8_t *key, uint8_t *iv, uint32_t iv_len,
						   uint8_t *ciphertext, uint8_t *tag, uint32_t tag_len)
{
	int len;
	int ciphertext_len;
	int ret;

	/*
	* TODO(pending): replace legacy openssl functions
	* EVP_EncryptInit_ex, EVP_CIPHER_CTX_ctrl
	*/

	if (!initialized) {
		return -1;
	}

	/* Initialise the encryption operation. */
	ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
	if (ret != 1) {
		handle_errors();
	}

	/*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
	ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
	if (ret != 1) {
		handle_errors();
	}

	/* Initialise key and IV */
	ret = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
	if (ret != 1) {
		handle_errors();
	}

	/*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
	ret = EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);
	if (ret != 1) {
		handle_errors();
	}

	/*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
	ret = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
	if (ret != 1) {
		handle_errors();
	}
	ciphertext_len = len;

	/*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
	ret = EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
	if (ret != 1) {
		handle_errors();
	}
	ciphertext_len += len;

	/* Get the tag */
	ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag);
	if (ret != 1) {
		handle_errors();
	}

	return ciphertext_len;
}

int openssl_aesgcm_decrypt(uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *aad,
						   uint32_t aad_len, uint8_t *key, uint8_t *iv, uint32_t iv_len,
						   uint8_t *plaintext, uint8_t *tag, uint32_t tag_len)
{
	int len;
	int plaintext_len;
	int ret;

	/*
	* TODO(pending): replace legacy openssl functions
	* EVP_DecryptInit_ex, EVP_CIPHER_CTX_ctrl
	*/

	if (!initialized) {
		return -1;
	}

	/* Initialise the decryption operation. */
	ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
	if (!ret) {
		handle_errors();
	}

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
	if (!ret) {
		handle_errors();
	}

	/* Initialise key and IV */
	ret = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
	if (!ret) {
		handle_errors();
	}

	/*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
	ret = EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len);
	if (!ret) {
		handle_errors();
	}

	/*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
	ret = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
	if (!ret) {
		handle_errors();
	}
	plaintext_len = len;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag);
	if (!ret) {
		handle_errors();
	}

	/*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	if (ret > 0) {
		/* Success */
		plaintext_len += len;
		return plaintext_len;
	} else {
		/* Verify failed */
		return -1;
	}
}

int openssl_aesgcm_deinit(void)
{
	if (!initialized) {
		return 0;
	}

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	initialized = false;

	return 0;
}
