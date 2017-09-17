#include "encoding.h"
#include <string.h>

static const char* BASE64_MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(const unsigned char *data, size_t len, char *out, size_t outlen)
{
	size_t di = 0;
	size_t oi = 0;
	--outlen; // reserve a char for null termination

	while (di + 3 <= len && oi + 4 <= outlen)
	{
		out[oi] = BASE64_MAP[data[di] >> 2];
		out[oi + 1] = BASE64_MAP[((data[di] & 0x03) << 4) | (data[di + 1] >> 4)];
		out[oi + 2] = BASE64_MAP[((data[di + 1] & 0x0f) << 2) | (data[di + 2] >> 6)];
		out[oi + 3] = BASE64_MAP[data[di + 2] & 0x3f];

		di += 3;
		oi += 4;
	}

	if (outlen - oi >= 4)
	{
		if (len - di == 1)
		{
			out[oi] = BASE64_MAP[data[di] >> 2];
			out[oi + 1] = BASE64_MAP[(data[di] & 0x03) << 4];
			out[oi + 2] = '=';
			out[oi + 3] = '=';
		}
		else if (len - di == 2)
		{
			out[oi] = BASE64_MAP[data[di] >> 2];
			out[oi + 1] = BASE64_MAP[((data[di] & 0x03) << 4) | (data[di + 1] >> 4)];
			out[oi + 2] = BASE64_MAP[(data[di + 1] & 0x0f) << 2];
			out[oi + 3] = '=';
		}

		oi += 4;
	}

	out[oi] = 0;
}

void base64_decode(const char *str, unsigned char *out, size_t outlen, size_t *bytes_written)
{
	size_t si = 0;
	size_t vsi = 0;
	size_t oi = 0;
	char buf[4];

	while (str[si] != 0 && oi < outlen)
	{
		char *pos = NULL;

		if (str[si] == '=')
		{
			break;
		}

		pos = strchr(BASE64_MAP, str[si++]);

		if (pos == NULL)
		{
			continue;
		}

		buf[vsi % 4] = (char)(pos - BASE64_MAP);

		++vsi;

		if (vsi % 4 == 0)
		{
			out[oi++] = buf[0] << 2 | buf[1] >> 4;
			out[oi++] = buf[1] << 4 | buf[2] >> 2;
			out[oi++] = buf[2] << 6 | buf[3];
		}
	}

	if (si % 4 > 1 && oi < outlen)
	{
		out[oi++] = buf[0] << 2 | buf[1] >> 4;
	}

	if (si % 4 == 3 && oi < outlen)
	{
		out[oi++] = buf[1] << 4 | buf[2] >> 2;
	}

	if (bytes_written != NULL)
	{
		*bytes_written = oi;
	}
}

void hex_encode(const unsigned char *data, size_t len, char *out, size_t outlen)
{
	size_t di = 0;
	size_t oi = 0;
	--outlen; // reserve a char for null termination

	while (di < len && oi + 2 <= outlen)
	{
		unsigned char h = data[di] >> 4;
		unsigned char l = data[di] & 0x0f;

		out[oi] = h < 10 ? '0' + h : 'a' + h - 10;
		out[oi + 1] = l < 10 ? '0' + l : 'a' + l - 10;

		++di;
		oi += 2;
	}

	out[oi] = 0;
}

void hex_decode(const char *str, unsigned char *out, size_t outlen, size_t *bytes_written)
{
	size_t si = 0;
	size_t oi = 0;
	char buf[2];

	while (str[si] != 0 && oi < outlen)
	{
		buf[si % 2] = str[si];
		++si;

		if (si % 2 == 0)
		{
			out[oi++] = (buf[0] >= '0' && buf[0] <= '9' ? buf[0] - '0' : buf[0] - 'a' + 10) << 4
				| (buf[1] >= '0' && buf[1] <= '9' ? buf[1] - '0' : buf[1] - 'a' + 10);
		}
	}

	if (bytes_written != NULL)
	{
		*bytes_written = oi;
	}
}
