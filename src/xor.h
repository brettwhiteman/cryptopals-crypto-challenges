#ifndef CRYPTOPALS_XOR_H
#define CRYPTOPALS_XOR_H

#include <stddef.h>

struct xor_key_list
{
	struct
	{
		unsigned char *data;
		size_t len;
	} *keys;
	size_t len;
};

void xor_perform(const unsigned char *data, size_t len, size_t stride, const unsigned char *key, size_t keylen, unsigned char *out, size_t outlen);
float xor_english_str_score(unsigned char *data, size_t len);
int xor_key_guess_sb(const unsigned char *data, size_t len, size_t stride, unsigned char *result);
struct xor_key_list *xor_key_list_new(void);
void xor_key_list_free(struct xor_key_list *list);
int xor_key_guess_mb(const unsigned char *data, size_t len, struct xor_key_list *out, int minlen, int maxlen, int numresults);

#endif
