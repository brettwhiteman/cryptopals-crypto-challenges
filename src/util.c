#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

int util_read_file(const char *filename, unsigned char **out, size_t *bytes_read, int null_terminate)
{
	FILE *file = NULL;
	off_t len = 0;
	size_t read = 0;
	*out = NULL;

	if ((file = fopen(filename, "r")) == NULL)
	{
		goto err;
	}

	if (fseeko(file, 0, SEEK_END))
	{
		goto err_close;
	}

	if ((len = ftello(file)) == -1)
	{
		goto err_close;
	}

	if (fseeko(file, 0, SEEK_SET))
	{
		goto err_close;
	}

	if ((*out = malloc(len + (null_terminate ? 1 : 0))) == NULL)
	{
		goto err_close;
	}

	read = fread(*out, 1, len, file);

	if (bytes_read != NULL)
	{
		*bytes_read = read;
	}

	if (null_terminate)
	{
		(*out)[read] = 0;
	}

	fclose(file);
	return 0;

err_close:
	fclose(file);
err:
	return 1;
}

char *util_str_lines(char *str, char **ctx)
{
	char *s = strtok_r(str, "\n", ctx);
	size_t len = 0;

	if (s == NULL)
	{
		return s;
	}

	len = strlen(s);

	if (s[len - 1] == '\r')
	{
		s[len - 1] = 0;
	}

	return s;
}
