#include <wolfssl/wolfcrypt/aes.h>
#include <stdint.h>
#include <stdbool.h>

#include "wolfssl_caller.h"

static Aes aes;
static bool initialized;

int wolfssl_aesgcm_init(void)
{
	int ret = -1;

	ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
	if (!ret) {
		initialized = true;
	}

	return ret;
}

int wolfssl_aesgcm_encrypt(uint8_t *plaintext, uint32_t plaintext_len, uint8_t *aad,
						   uint32_t aad_len, uint8_t *key, uint8_t *iv, uint32_t iv_len,
						   uint8_t *ciphertext, uint8_t *tag, uint32_t tag_len)
{
	int ret;

	if (!initialized) {
		goto ERROR;
	}

	ret = wc_AesGcmSetKey(&aes, key, 256 / 8);
	if (ret) {
		goto ERROR;
	}

	tag_len = (tag_len < 12) ? 12 : tag_len;
	ret		= wc_AesGcmEncrypt(&aes, ciphertext, plaintext, plaintext_len, iv, iv_len, tag, tag_len,
							   aad, aad_len);
	if (ret) {
		goto ERROR;
	}

	return plaintext_len;

ERROR:
	return -1;
}

int wolfssl_aesgcm_decrypt(uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *aad,
						   uint32_t aad_len, uint8_t *key, uint8_t *iv, uint32_t iv_len,
						   uint8_t *plaintext, uint8_t *tag, uint32_t tag_len)
{
	int ret;

	if (!initialized) {
		goto ERROR;
	}

	ret = wc_AesGcmSetKey(&aes, key, 256 / 8);
	if (ret) {
		goto ERROR;
	}

	ret = wc_AesGcmDecrypt(&aes, plaintext, ciphertext, ciphertext_len, iv, iv_len, tag, tag_len,
						   aad, aad_len);
	if (ret) {
		goto ERROR;
	}

	return ciphertext_len;

ERROR:
	return -1;
}

int wolfssl_aesgcm_deinit(void)
{
	if (!initialized) {
		goto OUT;
	}

	wc_AesFree(&aes);
	initialized = false;

OUT:
	return 0;
}
