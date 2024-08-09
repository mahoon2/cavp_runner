#include "main.h"
#include "binary_memory_stream.h"
#include "utility.h"

#include "cipher_aesgcm.h"

int verbose = 0;
static TARGET target;

extern int optind;
extern char *optarg;

static void parse_argv(TARGET *target_buf, const int argc, char *argv[])
{
	int ret;

	ret = getopt(argc, argv, "v:t:");
	do {
		switch (ret) {
		case 'v':
			verbose = atoi(optarg);
			if (verbose < 0 || verbose > 2) {
				retrieve_error(1);
			}
			printf("Setting VERBOSE level as %d\n", verbose);
			break;

		case 't':
			if (strcmp("openssl", optarg) == 0) {
				*target_buf = OPENSSL;
			} else if (strcmp("wolfssl", optarg) == 0) {
				*target_buf = WOLFSSL;
			} else {
				fprintf(stderr, "[ERROR] Supported target(s): openssl, wolfssl");
				retrieve_error(1);
			}
			printf("Setting target %s\n", optarg);
			break;

		default:
			fprintf(stderr, "[ERROR] Usage: %s [-v VERBOSITY] [-t TARGET] CRYPTO FILENAME\n",
					argv[0]);
			retrieve_error(1);
		}
		ret = getopt(argc, argv, "v:t:");
	} while (ret != -1);
}

bool is_running_on_device(void)
{
	return false;
}

int main(int argc, char *argv[])
{
	bool device_flag;
	struct binary_memory_stream stream;

	parse_argv(&target, argc, argv);

	device_flag = is_running_on_device();
	if (!device_flag) {
		if (optind == argc - 1) {
			fprintf(stderr, "[ERROR] Usage: %s [-v VERBOSITY] [-t TARGET] CRYPTO FILENAME\n",
					argv[0]);
			retrieve_error(1);
			return 0;
		}
		dump_bin_to_mem_stream(&stream, argv[optind + 1]);
	}

	aesgcm_cipher(target, &stream);

	if (!device_flag) {
		free_mem_ptr(&stream);
	}

	return 0;
}
