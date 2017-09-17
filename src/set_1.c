#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "set_1.h"
#include "encoding.h"
#include "xor.h"
#include "util.h"

void set_1_challenge_1()
{
	const char *input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	const char *expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
	unsigned char bytes[48];
	char base64[65];

	hex_decode(input, bytes, 48, NULL);
	base64_encode(bytes, 48, base64, 65);

	printf("Set 1 Challenge 1: %s\n", strcmp(base64, expected) == 0 ? "PASS" : "FAIL");
}

void set_1_challenge_2()
{
	const char *input1 = "1c0111001f010100061a024b53535009181c";
	const char *input2 = "686974207468652062756c6c277320657965";
	const char *expected = "746865206b696420646f6e277420706c6179";
	unsigned char bytes1[18];
	unsigned char bytes2[18];
	unsigned char xored[18];
	char xored_hex[37];

	hex_decode(input1, bytes1, 18, NULL);
	hex_decode(input2, bytes2, 18, NULL);
	xor_perform(bytes1, 18, 1, bytes2, 18, xored, 18);
	hex_encode(xored, 18, xored_hex, 37);

	printf("Set 1 Challenge 2: %s\n", strcmp(xored_hex, expected) == 0 ? "PASS" : "FAIL");
}

void set_1_challenge_3()
{
	const char *input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
	const char *expected = "Cooking MC's like a pound of bacon";
	unsigned char bytes[34];
	unsigned char bytes_decrypted[35];
	unsigned char key;

	hex_decode(input, bytes, 34, NULL);
	xor_key_guess_sb(bytes, 34, 1, &key);
	xor_perform(bytes, 34, 1, &key, 1, bytes_decrypted, 34);
	bytes_decrypted[34] = 0;

	printf("Set 1 Challenge 3: %s\n", strcmp((char *)bytes_decrypted, expected) == 0 ? "PASS" : "FAIL");
}

void set_1_challenge_4()
{
	const char *print = "Set 1 Challenge 4: %s\n";
	const char *expected = "Now that the party is jumping\n";
	char *input = NULL;
	char *result = NULL;
	unsigned char *buf = NULL;
	float max_score = 0.0f;
	char *ctx = NULL;
	char *line;
	size_t buflen = 0;

	if (util_read_file("files/4.txt", (unsigned char **)&input, NULL, 1))
	{
		goto err;
	}

	line = util_str_lines(input, &ctx);

	while (line != NULL)
	{
		size_t len = strlen(line);
		float score = 0.0f;
		unsigned char key;

		if (len == 0)
		{
			goto nextline;
		}

		len = (len + 1) / 2;

		if (buf == NULL || len > buflen) // re-use buffer if it's big enough
		{
			free(buf);
			buflen = len;
			buf = malloc(buflen + 1); // + 1 for null-terminate

			if (buf == NULL)
			{
				goto err;
			}
		}

		hex_decode(line, buf, buflen, &len);

		if (len == 0)
		{
			goto nextline;
		}

		if (xor_key_guess_sb(buf, len, 1, &key))
		{
			goto err;
		}

		xor_perform(buf, len, 1, &key, 1, buf, buflen);
		score = xor_english_str_score(buf, len);

		if (score > max_score)
		{
			max_score = score;
			buf[len] = 0;
			free(result);
			result = (char *)buf;
			buf = NULL;
		}

	nextline:
		line = util_str_lines(NULL, &ctx);
	}

	printf(print, strcmp(result, expected) == 0 ? "PASS" : "FAIL");
	free(input);
	free(buf);
	free(result);
	return;

err:
	printf(print, "FAIL");
	free(input);
	free(buf);
	free(result);
}

void set_1_challenge_5()
{
	const char *input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
	const char *expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
	unsigned char buf[74];
	char hex[149];

	xor_perform((const unsigned char *)input, 74, 1, (const unsigned char *)"ICE", 3, buf, 75);
	hex_encode(buf, 74, hex, 149);

	printf("Set 1 Challenge 5: %s\n", strcmp(hex, expected) == 0 ? "PASS" : "FAIL");
}

void set_1_challenge_6()
{
	const char *print = "Set 1 Challenge 6: %s\n";
	const char *expected = "Terminator X: Bring the noise";
	char *base64 = NULL;
	unsigned char *data = NULL;
	struct xor_key_list *xkl = NULL;
	size_t base64len = 0;
	size_t buflen = 0;
	size_t datalen = 0;
	char key[51];

	if (util_read_file("files/6.txt", (unsigned char **)&base64, &base64len, 1))
	{
		goto err;
	}

	buflen = base64len * 3 / 4;
	data = malloc(buflen);

	if (data == NULL)
	{
		goto err;
	}

	base64_decode(base64, data, buflen, &datalen);
	free(base64);
	base64 = NULL;

	xkl = xor_key_list_new();

	if (xor_key_guess_mb(data, datalen, xkl, 2, 40, 5))
	{
		goto err;
	}

	for (size_t i = 0; i < xkl->len; ++i)
	{
		memcpy(key, xkl->keys[i].data, xkl->keys[i].len);
		key[xkl->keys[i].len] = 0;

		if (strcmp(key, expected) == 0)
		{
			printf(print, "PASS");
			goto cleanup;
		}
	}

err:
	printf(print, "FAIL");
cleanup:
	free(base64);
	free(data);
	xor_key_list_free(xkl);
}

void set_1_challenge_7()
{
	const char *print = "Set 1 Challenge 7: %s\n";
	char *base64 = NULL;
	size_t base64len = 0;
	unsigned char *data = NULL;
	unsigned char *decrypted = NULL;
	size_t buflen = 0;
	size_t datalen = 0;
	const unsigned char *key = (const unsigned char *)"YELLOW SUBMARINE";
	EVP_CIPHER_CTX *cipher = NULL;
	int written = 0;
	int total = 0;

	if (util_read_file("files/7.txt", (unsigned char **)&base64, &base64len, 1))
	{
		goto err;
	}

	buflen = base64len * 3 / 4;
	data = malloc(buflen);

	if (data == NULL)
	{
		goto err;
	}

	base64_decode(base64, data, buflen, &datalen);
	decrypted = malloc(datalen + 17);

	if (decrypted == NULL)
	{
		goto err;
	}

	cipher = EVP_CIPHER_CTX_new();

	if (cipher == NULL)
	{
		goto err;
	}

	if (!EVP_DecryptInit_ex(cipher, EVP_aes_128_ecb(), NULL, key, NULL))
	{
		goto err;
	}

	if (!EVP_DecryptUpdate(cipher, decrypted, &written, data, datalen))
	{
		goto err;
	}

	total += written;

	if (!EVP_DecryptFinal(cipher, decrypted + written, &written))
	{
		goto err;
	}

	total += written;
	decrypted[total] = 0;

	if (strstr((char *)decrypted, "Play that funky music") != NULL)
	{
		printf(print, "PASS");
		goto cleanup;
	}

err:
	printf(print, "FAIL");
cleanup:
	free(base64);
	free(data);
	free(decrypted);

	if (cipher != NULL)
	{
		EVP_CIPHER_CTX_free(cipher);
	}
}
