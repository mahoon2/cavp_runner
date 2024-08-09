#ifndef BINARY_MEMORY_STREAM_H
#define BINARY_MEMORY_STREAM_H

struct binary_memory_stream {
	int offset;
	uint32_t mem_size;
	uint8_t *mem_ptr;
};

void dump_bin_to_mem_stream(struct binary_memory_stream *buf, const char *filename);
size_t mem_read(void *buf, const size_t size, struct binary_memory_stream *stream);
bool check_eof(struct binary_memory_stream *stream);
void free_mem_ptr(struct binary_memory_stream *stream);

#endif // BINARY_MEMORY_STREAM_H
