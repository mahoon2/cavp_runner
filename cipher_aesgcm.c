#include "main.h"
#include "utility.h"
#include "cipher_aesgcm.h"

#include "openssl_caller.h"
#include "wolfssl_caller.h"

#define ALIGN(a, b)		   (((a) + (b)-1) / (b)) * (b)
#define ACVTS_MAX_TEXT_LEN 8192
#define ACVTS_MAX_TAG_LEN  1024

static const uint32_t PACKET_TYPE_MASK = 0xC0000000;

static bool acvts_flag;
static uint8_t textbuf[ACVTS_MAX_TEXT_LEN];
static uint8_t tagbuf[ACVTS_MAX_TAG_LEN];
static uint8_t bytebuf[16];
static uint32_t vs_id;

void register_callbacks(struct aesgcm *buf, TARGET target)
{
	if (target == OPENSSL) {
		buf->init	 = openssl_aesgcm_init;
		buf->encrypt = openssl_aesgcm_encrypt;
		buf->decrypt = openssl_aesgcm_decrypt;
		buf->deinit	 = openssl_aesgcm_deinit;
	} else if (target == WOLFSSL) {
		buf->init	 = wolfssl_aesgcm_init;
		buf->encrypt = wolfssl_aesgcm_encrypt;
		buf->decrypt = wolfssl_aesgcm_decrypt;
		buf->deinit	 = wolfssl_aesgcm_deinit;
	}
	else {
		/* Invalid target */
		retrieve_error(1);
	}
}

static int parse_crypto_packet(struct aesgcm *gcm_buf, struct crypto_packet_header *crypto_hdr,
							   struct binary_memory_stream *stream)
{
	uint16_t payload_size = crypto_hdr->payload_size << 2;
	CRYPTO_ALGORITHM algo = crypto_hdr->algorithm;
	acvts_flag			  = crypto_hdr->acvts_flag;

	DEBUG(2, "Packet(upper) header info\n");
	DEBUG(2, "payload_size: %u\n", payload_size);
	DEBUG(2, "Crypto(lower) header info\n");
	DEBUG(2, "algo: %d | acvts: %d\n", algo, acvts_flag);

	if (algo != CIPHER_AESGCM) {
		fprintf(stderr, "[ERROR] Invalid crypto algorithm while %s\n", __func__);
		retrieve_error(1);
		return -1;
	}

	// Read out total binary size info (unused since binary_memory_stream already read this)
	mem_read(bytebuf, sizeof(uint32_t), stream);

	if (acvts_flag) {
		mem_read(bytebuf, sizeof(vs_id), stream);
		vs_id = (*(uint32_t *)bytebuf);
		DEBUG(2, "vsId: %d\n", vs_id);
	}

	return 0;
}

static int parse_config_packet(struct aesgcm_test_case *tc_buf,
							   struct config_packet_header *config_hdr,
							   struct binary_memory_stream *stream)
{
	int ret;
	uint16_t payload_size = config_hdr->payload_size << 2;
	int num_configs		  = config_hdr->num;
	CONFIG_DIRECTION dir  = config_hdr->direction;

	DEBUG(2, "Packet(upper) header info\n");
	DEBUG(2, "payload_size: %u\n", payload_size);
	DEBUG(2, "Config(lower) header info\n");
	DEBUG(2, "# of configs: %d | dir: %d\n", num_configs, dir);

	tc_buf->direction = dir;

	if ((!acvts_flag && (num_configs != payload_size / 4)) ||
		(acvts_flag && (num_configs != (payload_size - 4) / 4))) {
		fprintf(stderr, "[ERROR] # of config mismatch while %s\n", __func__);
		retrieve_error(1);
		return -1;
	} else {
		mem_read(bytebuf, sizeof(tc_buf->key_len), stream);
		tc_buf->key_len = (*(uint32_t *)bytebuf) / 8;

		mem_read(bytebuf, sizeof(tc_buf->iv_len), stream);
		tc_buf->iv_len = (*(uint32_t *)bytebuf) / 8;

		mem_read(bytebuf, sizeof(tc_buf->text_len), stream);
		tc_buf->text_len = (*(uint32_t *)bytebuf) / 8;

		mem_read(bytebuf, sizeof(tc_buf->aad_len), stream);
		tc_buf->aad_len = (*(uint32_t *)bytebuf) / 8;

		mem_read(bytebuf, sizeof(tc_buf->tag_len), stream);
		tc_buf->tag_len = (*(uint32_t *)bytebuf) / 8;
	}

	if (acvts_flag) {
		mem_read(bytebuf, sizeof(tc_buf->tg_id), stream);
		tc_buf->tg_id = (*(uint32_t *)bytebuf);
	}

	ret = is_running_on_device();
	if ((ret) && (tc_buf->iv_len != 12 || tc_buf->tag_len != 16 ||
				  (tc_buf->text_len == 0 && tc_buf->aad_len == 0))) {
		fprintf(stderr, "[ERROR] K2 only supports 12 bytes iv and 16 bytes tag\n");
		fprintf(stderr, "[ERROR] K2 only supports text and aad len are not both 0\n");
		retrieve_error(1);
		return -1;
	}

	printf("\n##### Test group configs info #####\n");
	printf("\tKeylen = %4u bytes\n", tc_buf->key_len);
	printf("\tIVlen  = %4u bytes\n", tc_buf->iv_len);
	printf("\tPTlen  = %4u bytes\n", tc_buf->text_len);
	printf("\tAADlen = %4u bytes\n", tc_buf->aad_len);
	printf("\tTaglen = %4u bytes\n", tc_buf->tag_len);

	return 0;
}

static int parse_test_case_packet(struct aesgcm_test_case *tc_buf,
								  struct test_case_packet_header *tc_hdr,
								  struct binary_memory_stream *stream)
{
	uint16_t payload_size	= tc_hdr->payload_size << 2;
	TEST_CASE_RESULT result = tc_hdr->result;

	DEBUG(2, "Packet header info\n");
	DEBUG(2, "payload_size: %u\n", payload_size);
	DEBUG(2, "Test case(lower) header info\n");
	DEBUG(2, "tc result: %s\n", (result == PASS) ? "PASS" : "FAIL");

	tc_buf->result = result;

	tc_buf->key = stream->mem_ptr + stream->offset;
	stream->offset += ALIGN((int)tc_buf->key_len, 4);

	tc_buf->iv = stream->mem_ptr + stream->offset;
	stream->offset += ALIGN((int)tc_buf->iv_len, 4);

	tc_buf->ct = stream->mem_ptr + stream->offset;
	stream->offset += ALIGN((int)tc_buf->text_len, 4);

	tc_buf->aad = stream->mem_ptr + stream->offset;
	stream->offset += ALIGN((int)tc_buf->aad_len, 4);

	tc_buf->tag = stream->mem_ptr + stream->offset;
	stream->offset += ALIGN((int)tc_buf->tag_len, 4);

	tc_buf->pt = stream->mem_ptr + stream->offset;
	stream->offset += ALIGN((int)tc_buf->text_len, 4);

	if (acvts_flag) {
		mem_read(bytebuf, sizeof(tc_buf->tc_id), stream);
		tc_buf->tc_id = (*(uint32_t *)bytebuf);
	}

	// fwrite_hex_as_string(2, tc_buf->key, tc_buf->key_len, stdout);
	// fwrite_hex_as_string(2, tc_buf->iv, tc_buf->iv_len, stdout);
	// fwrite_hex_as_string(2, tc_buf->ct, tc_buf->text_len, stdout);
	// fwrite_hex_as_string(2, tc_buf->aad, tc_buf->aad_len, stdout);
	// fwrite_hex_as_string(2, tc_buf->tag, tc_buf->tag_len, stdout);
	// fwrite_hex_as_string(2, tc_buf->pt, tc_buf->text_len, stdout);

	return 0;
}

static bool is_answer_correct(struct aesgcm_test_case *test_case,
							  struct aesgcm_test_result *test_result)
{
	int ret;
	bool test_result_wrong = false;
	uint8_t *testcase_text = (test_result->direction == ENCRYPT) ? test_case->ct : test_case->pt;

	DEBUG(2, "------------------------------------------------\n");

	/* Case 0: Test case marked as fail and indeed it failed */
	if (test_case->result == FAIL && test_result->result == FAIL) {
		goto OUT;
	}

	/* Case 1: SUCCESS/FAIL tag doesn't match */
	if (test_case->result == PASS && test_result->result == FAIL) {
		DEBUG(2, "TC was marked as pass but failed\n");
		test_result_wrong = true;
	}

	if (test_case->result == FAIL && test_result->result == PASS) {
		DEBUG(2, "TC was marked as fail but passed\n");
		test_result_wrong = true;
	}

	/* Case 2: Output text doesn't match */
	ret = memcmp(testcase_text, test_result->out_text, test_case->text_len);
	if (ret != 0) {
		DEBUG(2, "Text(bin): ");
		fwrite_hex_as_string(2, testcase_text, test_case->text_len, stderr);
		DEBUG(2, "Text(out): ");
		fwrite_hex_as_string(2, test_result->out_text, test_case->text_len, stderr);
		test_result_wrong = true;
	}

	/* Case 3: (If any) output tag doesn't match */
	if (test_result->direction == ENCRYPT) {
		ret = memcmp(test_case->tag, test_result->out_tag, test_case->tag_len);

		if (ret != 0) {
			DEBUG(2, "Tag(bin): ");
			fwrite_hex_as_string(2, test_case->tag, test_case->tag_len, stderr);
			DEBUG(2, "Tag(out): ");
			fwrite_hex_as_string(2, test_result->out_tag, test_case->tag_len, stderr);
			test_result_wrong = true;
		}
	}

OUT:
	if (test_result_wrong) {
		DEBUG(1, "FAILED TC\n");
		return false;
	} else {
		DEBUG(1, "PASSED TC\n");
		return true;
	}
}

static void print_group_result(int pass_tc_cnt, int fail_tc_cnt)
{
	if (acvts_flag) {
		printf("!!! END of test group !!!\n");
	} else if (fail_tc_cnt) {
		printf("!!! FAILED for %d test case(s) !!!\n", fail_tc_cnt);
	} else if (pass_tc_cnt) {
		printf("!!! PASSED all %d test case(s) !!!\n", pass_tc_cnt);
	}
}

/*
static void dump_crypto_packet_to_memory(void)
{
	uint32_t dummy	= 0;
	uint32_t pkt_hdr_int;
	struct crypto_packet_header pkt_hdr;

	pkt_hdr.packet_type	  = CRYPTO_PACKET;
	pkt_hdr.payload_size  = 8 >> 2;
	pkt_hdr.algorithm	  = CIPHER_AESGCM;
	pkt_hdr.acvts_flag	  = 1;
	pkt_hdr.response_flag = 1;

	memcpy(&pkt_hdr_int, &pkt_hdr, sizeof(pkt_hdr));

	DEBUG(2, "Current ptr: %p\n", mem_dump_ptr);
	DEBUG(2, "Dump crypto packet hdr: %08x\n", pkt_hdr_int);

	memcpy(mem_dump_ptr, &pkt_hdr_int, 4);
	mem_dump_ptr += sizeof(pkt_hdr_int);

	// TODO(pending): fill this total file size buffer?
	memcpy(mem_dump_ptr, &dummy, 4);
	mem_dump_ptr += sizeof(dummy);

	memcpy(mem_dump_ptr, &vs_id, 4);
	mem_dump_ptr += sizeof(vs_id);

	fwrite_hex_as_string(2, mem_dump_ptr - (sizeof(uint32_t) * 3), sizeof(uint32_t) * 3, stdout);
}

static void dump_config_packet_to_memory(CONFIG_DIRECTION dir, uint32_t tg_id, uint32_t text_len,
										 uint32_t tag_len)
{
	uint32_t pkt_hdr_int;
	struct config_packet_header pkt_hdr;

	pkt_hdr.packet_type = CONFIG_PACKET;
	pkt_hdr.direction	= dir;

	if (dir == ENCRYPT) {
		pkt_hdr.num			 = 2;
		pkt_hdr.payload_size = 12 >> 2;
	} else if (dir == DECRYPT) {
		pkt_hdr.num			 = 1;
		pkt_hdr.payload_size = 8 >> 2;
	}

	memcpy(&pkt_hdr_int, &pkt_hdr, sizeof(pkt_hdr));
	DEBUG(2, "Current ptr: %p\n", mem_dump_ptr);
	DEBUG(2, "Dump config packet hdr: %08x\n", pkt_hdr_int);

	memcpy(mem_dump_ptr, &pkt_hdr_int, 4);
	mem_dump_ptr += sizeof(pkt_hdr_int);

	memcpy(mem_dump_ptr, &tg_id, 4);
	mem_dump_ptr += sizeof(tg_id);

	memcpy(mem_dump_ptr, &text_len, 4);
	mem_dump_ptr += sizeof(text_len);

	if (dir == ENCRYPT) {
		memcpy(mem_dump_ptr, &tag_len, 4);
		mem_dump_ptr += sizeof(tag_len);
		fwrite_hex_as_string(2, mem_dump_ptr - (sizeof(uint32_t) * 4), sizeof(uint32_t) * 4,
							 stdout);
	} else {
		fwrite_hex_as_string(2, mem_dump_ptr - (sizeof(uint32_t) * 3), sizeof(uint32_t) * 3,
							 stdout);
	}
}

static void dump_test_case_packet_to_memory(TEST_CASE_RESULT result, uint32_t tc_id,
											uint8_t *text_out, uint32_t text_len, uint8_t *tag_out,
											uint32_t tag_len)
{
	uint32_t pkt_hdr_int = 0;
	struct test_case_packet_header pkt_hdr;

	pkt_hdr.packet_type = TEST_CASE_PACKET;
	pkt_hdr.result		= result;

	if (tag_out) {
		pkt_hdr.payload_size = (text_len + tag_len + 4) >> 2;
	} else {
		pkt_hdr.payload_size = (text_len + 4) >> 2;
	}

	memcpy(&pkt_hdr_int, &pkt_hdr, sizeof(pkt_hdr));
	DEBUG(2, "Current ptr: %p\n", mem_dump_ptr);
	DEBUG(2, "Dump test case packet hdr: %08x\n", pkt_hdr_int);

	memcpy(mem_dump_ptr, &pkt_hdr_int, 4);
	mem_dump_ptr += sizeof(pkt_hdr_int);

	memcpy(mem_dump_ptr, &tc_id, 4);
	mem_dump_ptr += sizeof(tc_id);

	fwrite_hex_as_string(2, mem_dump_ptr - (sizeof(uint32_t) * 2), sizeof(uint32_t) * 2, stdout);

	DEBUG(2, "Text: ");
	for (uint32_t bytes = 0; bytes < text_len; bytes++) {
		*mem_dump_ptr = *(text_out + bytes);
		DEBUG(2, "%02x", *mem_dump_ptr);
		mem_dump_ptr += 1;
	}
	DEBUG(2, "\n");

	if (tag_out) {
		DEBUG(2, "Tag: ");
		for (uint32_t bytes = 0; bytes < tag_len; bytes++) {
			*mem_dump_ptr = *(tag_out + bytes);
			DEBUG(2, "%02x", *mem_dump_ptr);
			mem_dump_ptr += 1;
		}
		DEBUG(2, "\n");
	}
}
*/

void aesgcm_cipher(TARGET target, struct binary_memory_stream *stream)
{
	int ret;
	int output_length = 0;
	int passed_tc_cnt = 0;
	int failed_tc_cnt = 0;
	bool device_flag;
	size_t read_bytes;
	uint32_t pkt_hdr;
	PACKET_TYPE pkt_type;
	CIPHER_STATE state = CIPHER_STATE_START;

	struct aesgcm gcm;
	struct aesgcm_test_case test_case;
	struct aesgcm_test_result test_result;

	device_flag = is_running_on_device();
	if (device_flag) {
		//mem_dump_ptr = mem_dump_start_addr;
	}

	memset(&gcm, 0, sizeof(gcm));
	memset(&test_case, 0, sizeof(test_case));
	register_callbacks(&gcm, target);
	gcm.init();

	while (1) {
		read_bytes = mem_read(&pkt_hdr, sizeof(pkt_hdr), stream);
		ret		   = check_eof(stream);
		if (read_bytes < sizeof(pkt_hdr) || ret) {
			fprintf(stderr, "Short count or EOF at %s\n", __func__);
			goto CLEAN;
		}

		DEBUG(2, "\nPacket header is: ");
		fwrite_hex_as_string(2, (uint8_t *)&pkt_hdr, sizeof(pkt_hdr), stderr);

		pkt_type = GET_PACKET_TYPE(pkt_hdr);
		DEBUG(2, "Packet type: %d\n", pkt_type);

		// TODO: Modify state machine
		switch (state) {
		case CIPHER_STATE_START:
			if (pkt_type == CRYPTO_PACKET) {
				DEBUG(2, "Parsing crypto packet\n");
				ret	  = parse_crypto_packet(&gcm, (struct crypto_packet_header *)&pkt_hdr, stream);
				state = CIPHER_STATE_WAITING_CONFIG;

				if (acvts_flag && device_flag) {
					// dump_crypto_packet_to_memory();
				}
			}
			break;

		case CIPHER_STATE_WAITING_CONFIG:
			if (pkt_type == CONFIG_PACKET) {
				DEBUG(2, "Parsing config packet\n");
				ret = parse_config_packet(&test_case, (struct config_packet_header *)&pkt_hdr,
										  stream);

				passed_tc_cnt = 0;
				failed_tc_cnt = 0;
				state		  = CIPHER_STATE_WAITING_TEST_CASE;

				if (acvts_flag && device_flag) {
					// dump_config_packet_to_memory(test_case.direction, test_case.tg_id,
					//							 test_case.text_len, test_case.tag_len);
				}
			}
			break;

		case CIPHER_STATE_WAITING_TEST_CASE:
			if (pkt_type == CONFIG_PACKET) {
				print_group_result(passed_tc_cnt, failed_tc_cnt);
				DEBUG(2, "Parsing config packet\n");
				ret = parse_config_packet(&test_case, (struct config_packet_header *)&pkt_hdr,
										  stream);

				passed_tc_cnt = 0;
				failed_tc_cnt = 0;
				state		  = CIPHER_STATE_WAITING_TEST_CASE;

				if (acvts_flag && device_flag) {
					// dump_config_packet_to_memory(test_case.direction, test_case.tg_id,
					//							 test_case.text_len, test_case.tag_len);
				}
			} else if (pkt_type == TEST_CASE_PACKET) {
				DEBUG(2, "Parsing test case packet\n");
				ret = parse_test_case_packet(&test_case, (struct test_case_packet_header *)&pkt_hdr,
											 stream);
				state = CIPHER_STATE_READY_FOR_RUNNING_TEST_CASE;
			}
			break;

		default:
			fprintf(stderr, "[ERROR] Incompatible packet type %d at %s\n", pkt_type, __func__);
			fprintf(stderr, "[ERROR] Packet header: ");
			fwrite_hex_as_string(0, (uint8_t *)&pkt_hdr, 4, stderr);
			retrieve_error(1);

			goto CLEAN;
		};

		if (ret) {
			fprintf(stderr, "Failed packet parsing with retval = %d at %s\n", ret, __func__);
			retrieve_error(1);
			goto CLEAN;
		}

		if (state == CIPHER_STATE_READY_FOR_RUNNING_TEST_CASE) {
			if (test_case.direction == ENCRYPT) {
				output_length = gcm.encrypt(test_case.pt, test_case.text_len, test_case.aad,
											test_case.aad_len, test_case.key, test_case.iv,
											test_case.iv_len, textbuf, tagbuf, test_case.tag_len);
			} else if (test_case.direction == DECRYPT) {
				output_length = gcm.decrypt(test_case.ct, test_case.text_len, test_case.aad,
											test_case.aad_len, test_case.key, test_case.iv,
											test_case.iv_len, textbuf, test_case.tag,
											test_case.tag_len);
			} else {
				retrieve_error(1);
			}

			state = CIPHER_STATE_WAITING_TEST_CASE;

			test_result.direction = test_case.direction;
			test_result.result	  = (output_length == test_case.text_len) ? PASS : FAIL;
			test_result.out_text  = textbuf;
			test_result.out_tag	  = (test_case.direction == ENCRYPT) ? tagbuf : NULL;

			if (acvts_flag) {
				DEBUG(0, "tgId: %u, tcId %u result\n", test_case.tg_id, test_case.tc_id);
				if (test_case.direction == ENCRYPT) {
					fwrite_hex_as_string(0, tagbuf, test_case.tag_len, stdout);
				}
				fwrite_hex_as_string(0, textbuf, test_case.text_len, stdout);

				// if (device_flag) {
				// 	dump_test_case_packet_to_memory(test_result.result, test_case.tc_id,
				// 									test_result.out_text, test_case.text_len,
				// 									test_result.out_tag, test_case.tag_len);
				// }
			} else {
				is_answer_correct(&test_case, &test_result) ? passed_tc_cnt++ : failed_tc_cnt++;
			}
		}
	}

CLEAN:
	print_group_result(passed_tc_cnt, failed_tc_cnt);
	// if (acvts_flag && device_flag) {
	// 	printf("Dumped addr range: %p to %p\n", mem_dump_start_addr, mem_dump_ptr);
	// }
	gcm.deinit();
}
