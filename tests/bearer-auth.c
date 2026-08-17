/*
 * Copyright (C) 2026 Microsoft Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#include <assert.h>
#include <string.h>

#include "../src/http-auth.h"

static void assert_bearer(const char *authorization)
{
	assert(http_auth_is_bearer(authorization, strlen(authorization)) != 0);
}

static void assert_not_bearer(const char *authorization)
{
	size_t size = authorization == NULL ? 0 : strlen(authorization);

	assert(http_auth_is_bearer(authorization, size) == 0);
}

int main(void)
{
	assert_bearer("Bearer token");
	assert_bearer("bearer token");
	assert_bearer("BEARER token");

	assert_not_bearer(NULL);
	assert_not_bearer("");
	assert_not_bearer("Bearer");
	assert_not_bearer("Bearer ");
	assert_not_bearer("Basic token");
	assert_not_bearer("Negotiate token");
	assert_not_bearer("BearerToken");

	return 0;
}
