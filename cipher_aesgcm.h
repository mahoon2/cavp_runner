#ifndef CIPHER_AESGCM_H
#define CIPHER_AESGCM_H

#include "binary_memory_stream.h"

#define PACKET_TYPE_OFFSET		   30
#define GET_PACKET_TYPE(x)		   (((x) & PACKET_TYPE_MASK) >> PACKET_TYPE_OFFSET)

struct crypto_packet_header {
	uint16_t reserved	  : 4;
	uint8_t response_flag : 1;
	uint8_t acvts_flag	  : 1;
	uint16_t algorithm	  : 10;

	uint16_t payload_size : 14;
	uint8_t packet_type	  : 2;
};

struct config_packet_header {
	uint16_t reserved : 10;
	uint8_t direction : 2;
	uint8_t num		  : 4;

	uint16_t payload_size : 14;
	uint8_t packet_type	  : 2;
};

struct test_case_packet_header {
	uint16_t reserved : 15;
	uint8_t result	  : 1;

	uint16_t payload_size : 14;
	uint8_t packet_type	  : 2;
};

typedef int (*aesgcm_crypto)(uint8_t *input_text, uint32_t text_len, uint8_t *aad, uint32_t add_len,
							 uint8_t *key, uint8_t *iv, uint32_t iv_len, uint8_t *output_text,
							 uint8_t *tag, uint32_t tag_len);

typedef enum {
	CIPHER_STATE_START = 0,
	CIPHER_STATE_WAITING_CONFIG,
	CIPHER_STATE_WAITING_TEST_CASE,
	CIPHER_STATE_READY_FOR_RUNNING_TEST_CASE,
} CIPHER_STATE;

typedef enum { CRYPTO_PACKET = 0, CONFIG_PACKET, TEST_CASE_PACKET } PACKET_TYPE;

typedef enum { CIPHER_AESGCM = 1 } CRYPTO_ALGORITHM;

typedef enum { ENCRYPT = 0, DECRYPT } CONFIG_DIRECTION;

typedef enum { FAIL = 0, PASS } TEST_CASE_RESULT;

struct aesgcm {
	int (*init)(void);
	aesgcm_crypto encrypt;
	aesgcm_crypto decrypt;
	int (*deinit)(void);
};

struct aesgcm_test_case {
	uint32_t key_len;
	uint32_t iv_len;
	uint32_t text_len;
	uint32_t aad_len;
	uint32_t tag_len;
	uint32_t tg_id;
	CONFIG_DIRECTION direction;

	uint8_t *key;
	uint8_t *iv;
	uint8_t *ct;
	uint8_t *aad;
	uint8_t *tag;
	uint8_t *pt;
	uint32_t tc_id;
	TEST_CASE_RESULT result;
};

struct aesgcm_test_result {
	CONFIG_DIRECTION direction;
	TEST_CASE_RESULT result;

	uint8_t *out_text;
	uint8_t *out_tag;
};

void register_callbacks(struct aesgcm *buf, TARGET target);
void aesgcm_cipher(TARGET target, struct binary_memory_stream *stream);

#endif // CIPHER_AESGCM_H
