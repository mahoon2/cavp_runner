#ifndef OPENSSL_CALLER_H
#define OPENSSL_CALLER_H

int openssl_aesgcm_init(void);
int openssl_aesgcm_encrypt(uint8_t *plaintext, uint32_t text_len, uint8_t *aad, uint32_t aad_len,
						   uint8_t *key, uint8_t *iv, uint32_t iv_len, uint8_t *ciphertext,
						   uint8_t *tag, uint32_t tag_len);

int openssl_aesgcm_decrypt(uint8_t *ciphertext, uint32_t text_len, uint8_t *aad, uint32_t aad_len,
						   uint8_t *key, uint8_t *iv, uint32_t iv_len, uint8_t *plaintext,
						   uint8_t *tag, uint32_t tag_len);
int openssl_aesgcm_deinit(void);

#endif // OPENSSL_CALLER_H
