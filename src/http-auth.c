/*
 * Copyright (C) 2026 Microsoft Corporation
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#include <strings.h>
#include "http-auth.h"

int http_auth_is_bearer(const char *authorization, size_t authorization_size)
{
	static const char prefix[] = HTTP_AUTH_BEARER_SCHEME " ";

	return authorization != NULL &&
	       authorization_size > sizeof(prefix) - 1 &&
	       strncasecmp(authorization, prefix, sizeof(prefix) - 1) == 0;
}
