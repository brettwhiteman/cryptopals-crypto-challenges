#ifndef CRYPTOCHALLENGE_UTIL_H
#define CRYPTOCHALLENGE_UTIL_H

#include <stdint.h>

int util_read_file(const char *filename, unsigned char **out, size_t *bytes_read, int null_terminate);
char *util_str_lines(char *str, char **ctx);

#endif
