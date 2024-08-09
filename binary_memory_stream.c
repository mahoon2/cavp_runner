#include "main.h"
#include "utility.h"
#include "binary_memory_stream.h"

void dump_bin_to_mem_stream(struct binary_memory_stream *buf, const char *filename)
{
	size_t filesize;
	size_t read_bytes;
	size_t packet_header_filesize;
	uint8_t *dumped_ptr;
	FILE *file = fopen(filename, "rb");

	if (!file) {
		/* Error while opening the file */
		fprintf(stderr, "[ERROR] Failed to open file at %s\n", __func__);
		retrieve_error(1);
	}

	fseek(file, 0, SEEK_END);
	filesize = ftell(file);
	rewind(file);

	dumped_ptr = malloc(filesize);
	if (!dumped_ptr) {
		fprintf(stderr, "[ERROR] malloc() failed at %s\n", __func__);
		retrieve_error(1);
	}

	read_bytes = fread(dumped_ptr, 1, filesize, file);
	if (filesize != read_bytes) {
		fprintf(stderr, "[ERROR] Short count reading binary file at %s\n", __func__);
		retrieve_error(1);
	}

	packet_header_filesize = *(uint32_t *)(dumped_ptr + 4);
	if (filesize != packet_header_filesize) {
		fprintf(stderr,
				"[ERROR] Real file size and file size written in packet doesn't match at %s\n",
				__func__);
		retrieve_error(1);
	}

	DEBUG(2, "Dumped %ld bytes to addr %p\n", read_bytes, dumped_ptr);

	buf->offset	  = 0;
	buf->mem_ptr  = dumped_ptr;
	buf->mem_size = filesize;

	fclose(file);
}

size_t mem_read(void *buf, const size_t size, struct binary_memory_stream *stream)
{
	size_t read_bytes =
		(size <= stream->mem_size - stream->offset) ? size : stream->mem_size - stream->offset;

	memcpy(buf, stream->mem_ptr + stream->offset, read_bytes);
	stream->offset += read_bytes;

	return read_bytes;
}

bool check_eof(struct binary_memory_stream *stream)
{
	return stream->offset == stream->mem_size;
}

void free_mem_ptr(struct binary_memory_stream *stream)
{
	free(stream->mem_ptr);
}
