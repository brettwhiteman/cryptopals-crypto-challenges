#ifndef CRYPTOPALS_ENCODING_H
#define CRYPTOPALS_ENCODING_H

#include <stddef.h>

void base64_encode(const unsigned char *data, size_t len, char *out, size_t outlen);
void base64_decode(const char *str, unsigned char *out, size_t outlen, size_t *bytes_written);
void hex_encode(const unsigned char *data, size_t len, char *out, size_t outlen);
void hex_decode(const char *str, unsigned char *out, size_t outlen, size_t *bytes_written);

#endif
