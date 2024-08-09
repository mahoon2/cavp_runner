#ifndef WOLFSSL_CALLER_H
#define WOLFSSL_CALLER_H

/* Error constants from wolfssl/wolfcrypt/error-crypt.h */
// #define BAD_FUNC_ARG   -173
// #define AES_GCM_AUTH_E -180
// #define INVALID_DEVID  -2

int wolfssl_aesgcm_init(void);
int wolfssl_aesgcm_encrypt(uint8_t *plaintext, uint32_t plaintext_len, uint8_t *aad,
						   uint32_t aad_len, uint8_t *key, uint8_t *iv, uint32_t iv_len,
						   uint8_t *ciphertext, uint8_t *tag, uint32_t tag_len);
int wolfssl_aesgcm_decrypt(uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *aad,
						   uint32_t aad_len, uint8_t *key, uint8_t *iv, uint32_t iv_len,
						   uint8_t *plaintext, uint8_t *tag, uint32_t tag_len);
int wolfssl_aesgcm_deinit(void);

#endif // WOLFSSL_CALLER_H
