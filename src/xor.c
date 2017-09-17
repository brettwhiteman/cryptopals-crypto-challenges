#include "xor.h"
#include <string.h>
#include <stdlib.h>

#define BIT(b, bit) (b & (1 << bit))

struct xor_ldp
{
	int len;
	float dist;
};

void xor_perform(const unsigned char *data, size_t len, size_t stride, const unsigned char *key, size_t keylen, unsigned char *out, size_t outlen)
{
	size_t di = 0;
	size_t ki = 0;
	size_t oi = 0;

	while (di < len && oi < outlen)
	{
		out[oi++] = data[di] ^ key[ki++];

		di += stride;

		if (ki == keylen)
		{
			ki = 0;
		}
	}
}

static float xor_english_char_score(unsigned char c)
{
	if (c == 'A' || c == 'a' || c == 'E' || c == 'e' || c == 'I' || c == 'i' || c == 'O' || c == 'o' || c == 'U' || c == 'u')
	{
		return 10.0f;
	}
	else if (c == ' ')
	{
		return 9.0f;
	}
	else if ((c >= 'a' && c <= 'z') || (c >= 'A' || c <= 'Z'))
	{
		return 6.0f;
	}
	else if (c == '.' || c == ',' || c == '\'' || c == ':')
	{
		return 3.0f;
	}

	return 0.0f;
}

float xor_english_str_score(unsigned char *data, size_t len)
{
	float score = 0.0f;
	size_t i;

	for (i = 0; i < len; ++i)
	{
		score += xor_english_char_score(data[i]);
	}

	return score / i;
}

int xor_key_guess_sb(const unsigned char *data, size_t len, size_t stride, unsigned char *result)
{
	float max_score = 0.0f;
	unsigned char *buf = malloc(len);

	if (buf == NULL)
	{
		return 1;
	}

	for (int key = 0; key < 256; ++key)
	{
		float score = 0.0f;

		xor_perform(data, len, stride, (unsigned char *)&key, 1, buf, len);
		score = xor_english_str_score(buf, len);

		if (score > max_score)
		{
			max_score = score;
			*result = key;
		}
	}

	free(buf);

	return 0;
}

static int xor_hamming_distance(const unsigned char *a, const unsigned char *b, size_t len)
{
	int numdiff = 0;

	for (size_t i = 0; i < len; ++i)
	{
		for (int bit = 0; bit < 8; ++bit)
		{
			if (BIT(a[i], bit) != BIT(b[i], bit))
			{
				++numdiff;
			}
		}
	}

	return numdiff;
}

static int xor_ldp_compare(const void *elem1, const void *elem2)
{
	return ((const struct xor_ldp *)elem1)->dist < ((const struct xor_ldp *)elem2)->dist ? -1 : 1;
}

static int xor_get_likely_key_lengths(const unsigned char *data, size_t len, int min, int max, int *out, size_t outlen)
{
	struct xor_ldp *sizes = NULL;

	if (min > max || max * 4 > len)
	{
		return 1;
	}

	sizes = malloc(sizeof(struct xor_ldp) * (max - min + 1));

	if (sizes == NULL)
	{
		return 1;
	}

	for (int i = min; i <= max; ++i)
	{
		int sum = xor_hamming_distance(&data[0], &data[i], i)
			+ xor_hamming_distance(&data[i], &data[i * 2], i)
			+ xor_hamming_distance(&data[i * 2], &data[i * 3], i);

		sizes[i - min].len = i;
		sizes[i - min].dist = (float)sum / 3.0f / i;
	}

	qsort(sizes, max - min + 1, sizeof(*sizes), xor_ldp_compare);

	for (size_t i = 0; i < outlen; ++i)
	{
		out[i] = sizes[i].len;
	}

	free(sizes);

	return 0;
}

struct xor_key_list *xor_key_list_new()
{
	struct xor_key_list *list = malloc(sizeof(struct xor_key_list));

	if (list == NULL)
	{
		return NULL;
	}

	memset(list, 0, sizeof(*list));

	return list;
}

void xor_key_list_free(struct xor_key_list *list)
{
	if (list == NULL)
	{
		return;
	}

	for (size_t i = 0; i < list->len; ++i)
	{
		free(list->keys[i].data);
		list->keys[i].data = NULL;
	}

	free(list->keys);
	list->keys = NULL;

	free(list);
}

int xor_key_guess_mb(const unsigned char *data, size_t len, struct xor_key_list *out, int minlen, int maxlen, int numresults)
{
	int *lengths = NULL;

	if (maxlen > len)
	{
		goto err;
	}

	if (maxlen - minlen + 1 < numresults)
	{
		numresults = maxlen - minlen + 1;
	}

	out->keys = malloc(sizeof(*out->keys) * numresults);

	if (out->keys == NULL)
	{
		goto err;
	}

	out->len = numresults;
	lengths = malloc(sizeof(*lengths) * numresults);

	if (lengths == NULL)
	{
		goto err;
	}

	if (xor_get_likely_key_lengths(data, len, minlen, maxlen, lengths, numresults))
	{
		goto err_free;
	}

	for (int i = 0; i < numresults; ++i)
	{
		out->keys[i].data = malloc(lengths[i]);

		if (out->keys[i].data == NULL)
		{
			goto err_free;
		}

		out->keys[i].len = lengths[i];

		for (int j = 0; j < lengths[i]; ++j)
		{
			if (xor_key_guess_sb(&data[j], len, lengths[i], &out->keys[i].data[j]))
			{
				goto err_free;
			}
		}
	}

	return 0;

err_free:
	free(lengths);
err:
	return 1;
}
