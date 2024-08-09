#include "main.h"
#include "utility.h"

void fwrite_hex_as_string(int verbose_level, uint8_t *ptr, size_t bytes, FILE *stream)
{
	if (verbose_level > verbose) {
		return;
	}

	for (size_t i = 0; i < bytes; i++) {
		fprintf(stream, "%02x", *ptr);
		ptr++;
	}

	fprintf(stream, "\n");
}

void retrieve_error(int err_code)
{
	/* No-return function */
	fprintf(stderr, "retrieve_error() called\n");
	/* TODO: define custom errno */

#ifndef DEVICE
	exit(EXIT_FAILURE);
#endif
}
