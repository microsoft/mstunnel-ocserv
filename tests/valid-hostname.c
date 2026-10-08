/*
 * Copyright (C) 2016 Nikos Mavrogiannopoulos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../src/valid-hostname.c"

/* This checks whether the valid_hostname() function works
 * as expected.
 */

char hostname[256];

unsigned int test_valid_hostname(const char *s)
{
	strncpy(hostname, s, sizeof(hostname) - 1);
	hostname[sizeof(hostname) - 1] = '\0';

	strip_domain(hostname);

	return valid_hostname(hostname);
}

int main(void)
{
	/* check invalid hostnames */
	assert(test_valid_hostname("192.168.1.1") == 0);
	assert(test_valid_hostname(".local") == 0);
	assert(test_valid_hostname(".abc.def") == 0);
	assert(test_valid_hostname("-hello") == 0);
	assert(test_valid_hostname("hello-") == 0);
	assert(test_valid_hostname("1234!") == 0);
	assert(test_valid_hostname("1234#abc") == 0);
	assert(test_valid_hostname("1234$abc") == 0);
	assert(test_valid_hostname("1234&abc") == 0);
	assert(test_valid_hostname("1234|abc") == 0);
	assert(test_valid_hostname("1234\aabc") == 0);
	assert(test_valid_hostname("1234\babc") == 0);
	/* 64-character label exceeds RFC 1123 §2.1 limit of 63 */
	assert(test_valid_hostname("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);

	/* check valid hostnames */
	/* 63-character label is the maximum allowed by RFC 1123 §2.1 */
	assert(test_valid_hostname("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") != 0);
	assert(test_valid_hostname("12-hello") != 0);
	assert(test_valid_hostname("1234abc-ABC") != 0);
	assert(test_valid_hostname("ABC-abc1") != 0);
	assert(test_valid_hostname("12345") != 0);
	assert(test_valid_hostname("ABC.abc") != 0 &&
	       strcmp(hostname, "ABC") == 0);
	assert(test_valid_hostname("aaa.bbb.ccc") != 0 &&
	       strcmp(hostname, "aaa") == 0);
	assert(test_valid_hostname("192.168.1.1234") != 0 &&
	       strcmp(hostname, "192") == 0);

	return 0;
}
