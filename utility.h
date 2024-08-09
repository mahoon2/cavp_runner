#ifndef UTILITY_H
#define UTILITY_H

void fwrite_hex_as_string(int verbose_level, uint8_t *ptr, size_t bytes, FILE *stream);
void retrieve_error(int err_code);

#endif // UTILITY_H
