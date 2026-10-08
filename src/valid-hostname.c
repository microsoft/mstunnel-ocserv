/*
 * Copyright (C) 2016 Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * ocserv is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/* Validates a single hostname label per RFC 952 as updated by RFC 1123:
 *  - first character: letter or digit (RFC 1123 relaxes RFC 952's letter-only rule)
 *  - interior characters: letters, digits, or hyphens
 *  - last character: letter or digit (no trailing hyphen)
 *  - maximum label length: 63 characters (RFC 1123 §2.1)
 */
unsigned int valid_hostname(const char *host)
{
	const char *p = host;

	if (p == NULL || *p == '\0' || *p == '-')
		return 0;

	while (*p != 0) {
		if (!(isalnum(*p)) && !(*p == '-'))
			return 0;
		p++;
	}

	if (*(p - 1) == '-')
		return 0;

	if ((p - host) > 63)
		return 0;

	return 1;
}

void strip_domain(char *host)
{
	char *dot;
	struct in_addr addr;

	if (host == NULL || host[0] == '.')
		return;

	/* do not strip if it's an IPv4 address */
	if (inet_pton(AF_INET, host, &addr) == 1)
		return;

	dot = strchr(host, '.');
	if (dot)
		*dot = '\0';
}
